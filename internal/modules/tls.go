package modules

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// AllCiphers returns all cipher suites (secure + insecure) so we can connect
// to legacy devices like printers that only support outdated TLS configs.
func AllCiphers() []uint16 {
	var ids []uint16
	for _, cs := range tls.CipherSuites() {
		ids = append(ids, cs.ID)
	}
	for _, cs := range tls.InsecureCipherSuites() {
		ids = append(ids, cs.ID)
	}
	return ids
}

// NewHTTPTransport creates an http.Transport with legacy TLS support and optional proxy.
// Supports socks5://, socks4://, socks4a://, http://, and https:// proxy URLs.
// Bare host:port defaults to socks5.
func NewHTTPTransport(proxyStr string) *http.Transport {
	t := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS10,
			CipherSuites:      AllCiphers(),
		},
	}
	if proxyStr != "" {
		normalized := NormalizeProxy(proxyStr)
		if strings.HasPrefix(normalized, "socks4://") || strings.HasPrefix(normalized, "socks4a://") {
			// Go's http.ProxyURL doesn't support socks4 — use custom DialContext
			t.DialContext = socks4DialContext(normalized)
		} else if proxyURL, err := url.Parse(normalized); err == nil {
			t.Proxy = http.ProxyURL(proxyURL)
		}
	}
	return t
}

// NormalizeProxy adds socks5:// scheme if no scheme is present.
func NormalizeProxy(s string) string {
	if s == "" {
		return s
	}
	if !strings.Contains(s, "://") {
		return "socks5://" + s
	}
	return s
}

// socks4DialContext returns a DialContext function that tunnels through a SOCKS4/4a proxy.
func socks4DialContext(proxyURL string) func(ctx context.Context, network, addr string) (net.Conn, error) {
	u, err := url.Parse(proxyURL)
	if err != nil || u.Host == "" {
		return func(ctx context.Context, network, addr string) (net.Conn, error) {
			return nil, fmt.Errorf("invalid socks4 proxy URL: %s", proxyURL)
		}
	}
	proxyHost := u.Host
	useSocks4a := strings.HasPrefix(proxyURL, "socks4a://")

	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		timeout := 30 * time.Second
		if deadline, ok := ctx.Deadline(); ok {
			timeout = time.Until(deadline)
		}

		conn, err := net.DialTimeout("tcp", proxyHost, timeout)
		if err != nil {
			return nil, fmt.Errorf("proxy connect: %w", err)
		}
		conn.SetDeadline(time.Now().Add(timeout))

		host, portStr, err := net.SplitHostPort(addr)
		if err != nil {
			conn.Close()
			return nil, err
		}
		port, _ := strconv.Atoi(portStr)

		req := []byte{0x04, 0x01, byte(port >> 8), byte(port & 0xff)}

		if useSocks4a {
			req = append(req, 0x00, 0x00, 0x00, 0x01) // 0.0.0.1
			req = append(req, 0x00)                    // empty userid
			req = append(req, []byte(host)...)
			req = append(req, 0x00)
		} else {
			ip := net.ParseIP(host)
			if ip == nil {
				addrs, err := net.LookupIP(host)
				if err != nil || len(addrs) == 0 {
					conn.Close()
					return nil, fmt.Errorf("socks4 cannot resolve %q", host)
				}
				ip = addrs[0]
			}
			ip4 := ip.To4()
			if ip4 == nil {
				conn.Close()
				return nil, fmt.Errorf("socks4 does not support IPv6")
			}
			req = append(req, ip4...)
			req = append(req, 0x00)
		}

		if _, err := conn.Write(req); err != nil {
			conn.Close()
			return nil, fmt.Errorf("socks4 connect: %w", err)
		}

		resp := make([]byte, 8)
		if _, err := io.ReadFull(conn, resp); err != nil {
			conn.Close()
			return nil, fmt.Errorf("socks4 response: %w", err)
		}
		if resp[1] != 0x5a {
			conn.Close()
			return nil, fmt.Errorf("socks4 connect refused (code 0x%02x)", resp[1])
		}

		conn.SetDeadline(time.Time{})
		return conn, nil
	}
}
