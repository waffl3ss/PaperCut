package scanner

import (
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// PJLResult holds the parsed response from PJL queries against a single host.
type PJLResult struct {
	IP           string
	Port         int
	RawID        string
	RawStatus    string
	Manufacturer string
	Model        string
	Online       bool
}

// Known manufacturer strings mapped to their canonical names.
var knownManufacturers = map[string]string{
	"hp":              "HP",
	"hewlett-packard":  "HP",
	"hewlett packard":  "HP",
	"ricoh":           "Ricoh",
	"xerox":           "Xerox",
	"sharp":           "Sharp",
	"brother":         "Brother",
	"canon":           "Canon",
	"lexmark":         "Lexmark",
	"konica minolta":  "Konica Minolta",
	"konica":          "Konica Minolta",
	"kyocera":         "Kyocera",
	"epson":           "Epson",
	"samsung":         "Samsung",
	"dell":            "Dell",
	"toshiba":         "Toshiba",
	"oki":             "OKI",
	"lanier":          "Ricoh", // Lanier is Ricoh rebrand
}

// QueryPJL connects to a host on the given port and sends PJL queries.
// If proxyAddr is set, the connection is tunneled through the SOCKS proxy.
func QueryPJL(ip string, port int, timeout time.Duration, proxyAddr string) (*PJLResult, error) {
	addr := net.JoinHostPort(ip, strconv.Itoa(port))
	var conn net.Conn
	var err error
	if proxyAddr != "" {
		if strings.HasPrefix(proxyAddr, "socks4://") || strings.HasPrefix(proxyAddr, "socks4a://") {
			conn, err = dialSOCKS4(proxyAddr, addr, timeout)
		} else {
			conn, err = dialSOCKS5(proxyAddr, addr, timeout)
		}
	} else {
		conn, err = net.DialTimeout("tcp", addr, timeout)
	}
	if err != nil {
		return nil, fmt.Errorf("connect %s: %w", addr, err)
	}
	defer conn.Close()

	result := &PJLResult{
		IP:   ip,
		Port: port,
	}

	// Query INFO ID
	conn.SetDeadline(time.Now().Add(timeout))
	rawID, err := pjlCommand(conn, "@PJL INFO ID\r\n")
	if err != nil {
		return nil, fmt.Errorf("PJL INFO ID on %s: %w", addr, err)
	}

	// Validate that the response looks like PJL (contains @PJL echo or a quoted model)
	if !isPJLResponse(rawID) {
		return nil, fmt.Errorf("non-PJL service on %s", addr)
	}

	result.RawID = rawID
	result.Model = parseInfoID(rawID)

	// If model is empty after parsing/sanitization, not a real printer
	if result.Model == "" {
		return nil, fmt.Errorf("no valid PJL model from %s", addr)
	}

	// Query INFO STATUS
	conn.SetDeadline(time.Now().Add(timeout))
	rawStatus, err := pjlCommand(conn, "@PJL INFO STATUS\r\n")
	if err == nil {
		result.RawStatus = rawStatus
		result.Online = strings.Contains(strings.ToUpper(rawStatus), "ONLINE=TRUE")
	}

	// Parse manufacturer from model string
	result.Manufacturer = identifyManufacturer(result.Model)

	return result, nil
}

// isPJLResponse checks if a raw response looks like a valid PJL response.
// Real PJL responses either echo back @PJL or contain a quoted model string.
func isPJLResponse(raw string) bool {
	if strings.Contains(raw, "@PJL") {
		return true
	}
	if strings.Contains(raw, "\"") {
		return true
	}
	return false
}

func pjlCommand(conn net.Conn, cmd string) (string, error) {
	_, err := conn.Write([]byte(cmd))
	if err != nil {
		return "", err
	}

	var result []byte
	buf := make([]byte, 4096)
	for {
		n, err := conn.Read(buf)
		if n > 0 {
			result = append(result, buf[:n]...)
			// PJL responses end with \f (form feed) or we have enough data
			if len(result) >= 4096 || strings.Contains(string(result), "\f") {
				break
			}
		}
		if err != nil {
			if len(result) > 0 {
				break
			}
			return "", err
		}
	}

	return strings.TrimSpace(strings.TrimRight(string(result), "\f")), nil
}

// parseInfoID extracts the model string from a PJL INFO ID response.
// Typical response: @PJL INFO ID\r\n"HP LaserJet Pro M404dn"\r\n
func parseInfoID(raw string) string {
	var model string

	// Try to find quoted string
	if idx := strings.Index(raw, "\""); idx >= 0 {
		rest := raw[idx+1:]
		if end := strings.Index(rest, "\""); end >= 0 {
			model = strings.TrimSpace(rest[:end])
		}
	}

	// Fall back: strip the @PJL INFO ID prefix and clean up
	if model == "" {
		model = raw
		model = strings.TrimPrefix(model, "@PJL INFO ID")
		model = strings.TrimSpace(model)
		model = strings.Trim(model, "\r\n\"")
	}

	return sanitizeModel(model)
}

// sanitizeModel cleans a raw model string: takes first line only, rejects
// non-PJL responses, and caps length at 128 characters.
func sanitizeModel(model string) string {
	// First line only — no model string should ever be multi-line
	if i := strings.IndexAny(model, "\r\n"); i >= 0 {
		model = strings.TrimSpace(model[:i])
	}

	if model == "" {
		return ""
	}

	lower := strings.ToLower(model)

	// HTTP responses
	if strings.HasPrefix(model, "HTTP/") || strings.Contains(lower, "bad request") {
		return ""
	}

	// POP3/IMAP banners
	if strings.HasPrefix(model, "+OK") || strings.HasPrefix(model, "+ok") || strings.HasPrefix(model, "* OK") {
		return ""
	}

	// SMTP/FTP banners (3-digit status code)
	if len(model) >= 4 && model[0] >= '1' && model[0] <= '5' && model[1] >= '0' && model[1] <= '9' && model[2] >= '0' && model[2] <= '9' && (model[3] == ' ' || model[3] == '-') {
		return ""
	}

	// SSH banners
	if strings.HasPrefix(model, "SSH-") {
		return ""
	}

	// rsync
	if strings.HasPrefix(model, "@RSYNCD:") {
		return ""
	}

	// HTML/XML fragments
	if strings.Contains(lower, "<!doctype") || strings.Contains(lower, "<html") ||
		strings.Contains(lower, "<head") || strings.Contains(lower, "//dtd") ||
		strings.Contains(lower, "//w3c") || strings.Contains(lower, "//ietf") {
		return ""
	}

	// CSS/HTTP header fragments
	cssHTTPPatterns := []string{"height:", "width:", "content-type", "content-language", "utf-8", "text/html", "charset"}
	for _, p := range cssHTTPPatterns {
		if strings.Contains(lower, p) {
			return ""
		}
	}

	// Non-printable / binary garbage
	for _, c := range model {
		if c < 32 && c != '\t' {
			return ""
		}
	}

	// Reject very short strings (1-2 chars) — not a real model name
	if len(model) <= 2 {
		return ""
	}

	// Cap length
	if len(model) > 128 {
		model = model[:128]
	}

	return model
}

// identifyManufacturer matches the model string against known manufacturers.
func identifyManufacturer(model string) string {
	lower := strings.ToLower(model)
	for keyword, canonical := range knownManufacturers {
		if strings.Contains(lower, keyword) {
			// Avoid false positive: "websocket-sharp" is not a Sharp printer
			if keyword == "sharp" && strings.Contains(lower, "websocket-sharp") {
				continue
			}
			return canonical
		}
	}
	return "Unknown"
}

// dialSOCKS4 connects to a target through a SOCKS4/4a proxy.
func dialSOCKS4(proxyAddr, target string, timeout time.Duration) (net.Conn, error) {
	pHost := proxyAddr
	if u, err := url.Parse(proxyAddr); err == nil && u.Host != "" {
		pHost = u.Host
	}
	useSocks4a := strings.HasPrefix(proxyAddr, "socks4a://")

	conn, err := net.DialTimeout("tcp", pHost, timeout)
	if err != nil {
		return nil, fmt.Errorf("proxy connect: %w", err)
	}
	conn.SetDeadline(time.Now().Add(timeout))

	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("parse target: %w", err)
	}
	port, _ := strconv.Atoi(portStr)

	// SOCKS4 request: VN(1) CD(1) DSTPORT(2) DSTIP(4) USERID(variable) NULL(1)
	req := []byte{
		0x04,                    // SOCKS version 4
		0x01,                    // CONNECT command
		byte(port >> 8),         // port high byte
		byte(port & 0xff),       // port low byte
	}

	if useSocks4a {
		// SOCKS4a: set IP to 0.0.0.x (x != 0) and append hostname after null userid
		req = append(req, 0x00, 0x00, 0x00, 0x01) // 0.0.0.1
		req = append(req, 0x00)                    // empty userid + null terminator
		req = append(req, []byte(host)...)          // hostname
		req = append(req, 0x00)                    // null terminator
	} else {
		// SOCKS4: resolve IP locally
		ip := net.ParseIP(host)
		if ip == nil {
			// Try DNS resolution
			addrs, err := net.LookupIP(host)
			if err != nil || len(addrs) == 0 {
				conn.Close()
				return nil, fmt.Errorf("socks4 cannot resolve %q (use socks4a:// for remote DNS)", host)
			}
			ip = addrs[0]
		}
		ip4 := ip.To4()
		if ip4 == nil {
			conn.Close()
			return nil, fmt.Errorf("socks4 does not support IPv6")
		}
		req = append(req, ip4...)
		req = append(req, 0x00) // empty userid + null terminator
	}

	if _, err := conn.Write(req); err != nil {
		conn.Close()
		return nil, fmt.Errorf("socks4 connect: %w", err)
	}

	// Response: VN(1) CD(1) DSTPORT(2) DSTIP(4) = 8 bytes
	resp := make([]byte, 8)
	if _, err := io.ReadFull(conn, resp); err != nil {
		conn.Close()
		return nil, fmt.Errorf("socks4 response: %w", err)
	}
	if resp[1] != 0x5a { // 0x5a = request granted
		conn.Close()
		return nil, fmt.Errorf("socks4 connect refused (code 0x%02x)", resp[1])
	}

	conn.SetDeadline(time.Time{})
	return conn, nil
}

// dialSOCKS5 connects to a target through a SOCKS5 proxy.
// proxyAddr can be "socks5://host:port", "host:port", or any URL with a host:port.
func dialSOCKS5(proxyAddr, target string, timeout time.Duration) (net.Conn, error) {
	// Parse proxy address — strip scheme if present
	pHost := proxyAddr
	if u, err := url.Parse(proxyAddr); err == nil && u.Host != "" {
		pHost = u.Host
	}

	// Connect to the SOCKS5 proxy
	conn, err := net.DialTimeout("tcp", pHost, timeout)
	if err != nil {
		return nil, fmt.Errorf("proxy connect: %w", err)
	}
	conn.SetDeadline(time.Now().Add(timeout))

	// SOCKS5 greeting: version 5, 1 auth method, no authentication
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		conn.Close()
		return nil, fmt.Errorf("socks5 handshake: %w", err)
	}
	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		conn.Close()
		return nil, fmt.Errorf("socks5 handshake: %w", err)
	}
	if resp[0] != 0x05 || resp[1] != 0x00 {
		conn.Close()
		return nil, fmt.Errorf("socks5 auth not supported by proxy (method: %d)", resp[1])
	}

	// CONNECT request
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("parse target: %w", err)
	}
	port, _ := strconv.Atoi(portStr)

	var req []byte
	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			req = append([]byte{0x05, 0x01, 0x00, 0x01}, ip4...)
		} else {
			req = append([]byte{0x05, 0x01, 0x00, 0x04}, ip.To16()...)
		}
	} else {
		// Domain name
		if len(host) > 255 {
			conn.Close()
			return nil, fmt.Errorf("socks5: domain name too long (%d bytes)", len(host))
		}
		req = append([]byte{0x05, 0x01, 0x00, 0x03, byte(len(host))}, host...)
	}
	req = append(req, byte(port>>8), byte(port&0xff))

	if _, err := conn.Write(req); err != nil {
		conn.Close()
		return nil, fmt.Errorf("socks5 connect: %w", err)
	}

	// Read CONNECT response header (4 bytes: ver, status, rsv, atype)
	resp = make([]byte, 4)
	if _, err := io.ReadFull(conn, resp); err != nil {
		conn.Close()
		return nil, fmt.Errorf("socks5 response: %w", err)
	}
	if resp[1] != 0x00 {
		conn.Close()
		return nil, fmt.Errorf("socks5 connect refused (code %d)", resp[1])
	}

	// Drain the bound address based on address type
	switch resp[3] {
	case 0x01: // IPv4: 4 bytes + 2 port
		io.ReadFull(conn, make([]byte, 4+2))
	case 0x03: // Domain: 1 len byte + domain + 2 port
		lenBuf := make([]byte, 1)
		io.ReadFull(conn, lenBuf)
		io.ReadFull(conn, make([]byte, int(lenBuf[0])+2))
	case 0x04: // IPv6: 16 bytes + 2 port
		io.ReadFull(conn, make([]byte, 16+2))
	}

	// Clear deadline — caller sets its own deadlines
	conn.SetDeadline(time.Time{})
	return conn, nil
}
