package workspace

import (
	"database/sql"
	"fmt"
	"strings"
	"time"
)

// Workspace represents a named workspace in the database.
type Workspace struct {
	ID        int64
	Name      string
	CreatedAt time.Time
	UpdatedAt time.Time
}

// ScanResult represents a single discovered printer.
type ScanResult struct {
	ID           int64
	WorkspaceID  int64
	IP           string
	Port         int
	Manufacturer string
	Model        string
	PJLRawID     string
	PJLRawStatus string
	Hostname     string
	ScannedAt    time.Time
}

// Create creates a new workspace with the given name.
func Create(name string) (*Workspace, error) {
	res, err := db.Exec("INSERT INTO workspaces (name) VALUES (?)", name)
	if err != nil {
		return nil, fmt.Errorf("create workspace %q: %w", name, err)
	}
	id, _ := res.LastInsertId()
	return Get(id)
}

// Get retrieves a workspace by ID.
func Get(id int64) (*Workspace, error) {
	w := &Workspace{}
	err := db.QueryRow("SELECT id, name, created_at, updated_at FROM workspaces WHERE id = ?", id).
		Scan(&w.ID, &w.Name, &w.CreatedAt, &w.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("get workspace id=%d: %w", id, err)
	}
	return w, nil
}

// GetByName retrieves a workspace by name.
// ErrNotFound is returned when a workspace lookup finds no matching record.
var ErrNotFound = fmt.Errorf("not found")

func GetByName(name string) (*Workspace, error) {
	w := &Workspace{}
	err := db.QueryRow("SELECT id, name, created_at, updated_at FROM workspaces WHERE name = ?", name).
		Scan(&w.ID, &w.Name, &w.CreatedAt, &w.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get workspace %q: %w", name, err)
	}
	return w, nil
}

// List returns all workspaces.
func List() ([]*Workspace, error) {
	rows, err := db.Query("SELECT id, name, created_at, updated_at FROM workspaces ORDER BY name")
	if err != nil {
		return nil, fmt.Errorf("list workspaces: %w", err)
	}
	defer rows.Close()

	var workspaces []*Workspace
	for rows.Next() {
		w := &Workspace{}
		if err := rows.Scan(&w.ID, &w.Name, &w.CreatedAt, &w.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan workspace row: %w", err)
		}
		workspaces = append(workspaces, w)
	}
	return workspaces, rows.Err()
}

// Delete removes a workspace and all its associated data.
func Delete(name string) error {
	res, err := db.Exec("DELETE FROM workspaces WHERE name = ?", name)
	if err != nil {
		return fmt.Errorf("delete workspace %q: %w", name, err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("workspace %q not found", name)
	}
	return nil
}

// ListNames returns just the workspace names (for tab completion).
func ListNames() ([]string, error) {
	rows, err := db.Query("SELECT name FROM workspaces ORDER BY name")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var names []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		names = append(names, name)
	}
	return names, rows.Err()
}

// InsertScanResult stores a scan result, using upsert to handle re-scans.
func InsertScanResult(r *ScanResult) error {
	_, err := db.Exec(`
		INSERT INTO scan_results (workspace_id, ip, port, manufacturer, model, pjl_raw_id, pjl_raw_status, hostname)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(workspace_id, ip, port) DO UPDATE SET
			manufacturer=excluded.manufacturer,
			model=excluded.model,
			pjl_raw_id=excluded.pjl_raw_id,
			pjl_raw_status=excluded.pjl_raw_status,
			hostname=excluded.hostname,
			scanned_at=CURRENT_TIMESTAMP
	`, r.WorkspaceID, r.IP, r.Port, r.Manufacturer, r.Model, r.PJLRawID, r.PJLRawStatus, r.Hostname)
	if err != nil {
		return fmt.Errorf("insert scan result: %w", err)
	}
	return nil
}

// GetScanResults retrieves scan results for a workspace, optionally filtered by manufacturer.
func GetScanResults(workspaceID int64, manufacturer string) ([]*ScanResult, error) {
	var query string
	var args []interface{}

	if manufacturer != "" {
		query = `SELECT id, workspace_id, ip, port, manufacturer, model, pjl_raw_id, pjl_raw_status, hostname, scanned_at
			FROM scan_results WHERE workspace_id = ? AND LOWER(manufacturer) = LOWER(?) ORDER BY ip`
		args = []interface{}{workspaceID, manufacturer}
	} else {
		query = `SELECT id, workspace_id, ip, port, manufacturer, model, pjl_raw_id, pjl_raw_status, hostname, scanned_at
			FROM scan_results WHERE workspace_id = ? ORDER BY ip`
		args = []interface{}{workspaceID}
	}

	rows, err := db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("get scan results: %w", err)
	}
	defer rows.Close()

	var results []*ScanResult
	for rows.Next() {
		r := &ScanResult{}
		if err := rows.Scan(&r.ID, &r.WorkspaceID, &r.IP, &r.Port, &r.Manufacturer, &r.Model,
			&r.PJLRawID, &r.PJLRawStatus, &r.Hostname, &r.ScannedAt); err != nil {
			return nil, fmt.Errorf("scan result row: %w", err)
		}
		results = append(results, r)
	}
	return results, rows.Err()
}

// GetManufacturers returns distinct manufacturers for a workspace (for tab completion).
func GetManufacturers(workspaceID int64) ([]string, error) {
	rows, err := db.Query(
		"SELECT DISTINCT manufacturer FROM scan_results WHERE workspace_id = ? AND manufacturer != '' ORDER BY manufacturer",
		workspaceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var manufacturers []string
	for rows.Next() {
		var m string
		if err := rows.Scan(&m); err != nil {
			return nil, err
		}
		manufacturers = append(manufacturers, m)
	}
	return manufacturers, rows.Err()
}

// ScanResultCount returns the number of scan results in a workspace.
func ScanResultCount(workspaceID int64) (int, error) {
	var count int
	err := db.QueryRow("SELECT COUNT(*) FROM scan_results WHERE workspace_id = ?", workspaceID).Scan(&count)
	return count, err
}

// CheckResult represents the outcome of a credential check against a target.
type CheckResult struct {
	ID          int64
	WorkspaceID int64
	ModuleName  string
	Target      string
	Port        int
	Success     bool
	Username    string
	Password    string
	Details     string
	CheckedAt   time.Time
}

// InsertCheckResult stores a check result, using upsert to handle re-checks.
func InsertCheckResult(r *CheckResult) error {
	_, err := db.Exec(`
		INSERT INTO check_results (workspace_id, module_name, target, port, success, username, password, details)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(workspace_id, module_name, target, port) DO UPDATE SET
			success=excluded.success,
			username=excluded.username,
			password=excluded.password,
			details=excluded.details,
			checked_at=CURRENT_TIMESTAMP
	`, r.WorkspaceID, r.ModuleName, r.Target, r.Port, r.Success, r.Username, r.Password, r.Details)
	if err != nil {
		return fmt.Errorf("insert check result: %w", err)
	}
	return nil
}

// ExploitResult represents the outcome of an exploitation attempt.
type ExploitResult struct {
	ID          int64
	WorkspaceID int64
	ModuleName  string
	Target      string
	Port        int
	Success     bool
	Username    string
	Password    string
	Details     string
	Data        string
	ExploitedAt time.Time
}

// InsertExploitResult stores an exploit result, using upsert to handle re-runs.
func InsertExploitResult(r *ExploitResult) error {
	_, err := db.Exec(`
		INSERT INTO exploit_results (workspace_id, module_name, target, port, success, username, password, details, data)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(workspace_id, module_name, target, port) DO UPDATE SET
			success=excluded.success,
			username=excluded.username,
			password=excluded.password,
			details=excluded.details,
			data=excluded.data,
			exploited_at=CURRENT_TIMESTAMP
	`, r.WorkspaceID, r.ModuleName, r.Target, r.Port, r.Success, r.Username, r.Password, r.Details, r.Data)
	if err != nil {
		return fmt.Errorf("insert exploit result: %w", err)
	}
	return nil
}

// Credential represents a captured credential from an exploit result.
type Credential struct {
	Target     string
	Port       int
	Username   string
	Password   string
	ModuleName string
	Protocol   string // e.g., "SMB", "FTP", "SMTP", "POP3", or "" for single-cred modules
}

// GetCredentials returns all captured credentials from successful exploits for a workspace.
// Parses the Data field to extract all credentials, including multi-credential modules.
func GetCredentials(workspaceID int64) ([]*Credential, error) {
	query := `
		SELECT target, port, module_name, data
		FROM exploit_results
		WHERE workspace_id = ? AND success = 1 AND data != ''
		ORDER BY target
	`

	rows, err := db.Query(query, workspaceID)
	if err != nil {
		return nil, fmt.Errorf("get credentials: %w", err)
	}
	defer rows.Close()

	var creds []*Credential
	for rows.Next() {
		var target, moduleName, data string
		var port int
		if err := rows.Scan(&target, &port, &moduleName, &data); err != nil {
			return nil, fmt.Errorf("scan credential row: %w", err)
		}
		for _, p := range ParseExploitData(data) {
			creds = append(creds, &Credential{
				Target:     target,
				Port:       port,
				Username:   p.Username,
				Password:   p.Password,
				ModuleName: moduleName,
				Protocol:   p.Protocol,
			})
		}
	}
	return creds, rows.Err()
}

// ParsedCred holds a single credential extracted from exploit result data.
type ParsedCred struct {
	Username string
	Password string
	Protocol string // "SMB", "FTP", "SMTP", "POP3", or ""
}

// ParseExploitData extracts all credentials from an exploit result's Data field.
// Handles multiple module data formats:
//   - Konica inline: "[SMB] Host: ... User: xxx Pass: yyy"
//   - Sharp MX-2640 prefixed: "POP3 Username: xxx\nPOP3 Password: yyy"
//   - Ricoh line-based: "DN: xxx\nPassword: yyy"
//   - Sharp MX-B468 line-based: "Username: xxx\nPassword: yyy"
func ParseExploitData(data string) []ParsedCred {
	if data == "" {
		return nil
	}

	lines := strings.Split(data, "\n")

	// Konica inline format: [Protocol] ... User: xxx Pass: yyy
	var results []ParsedCred
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "[") && strings.Contains(line, " User: ") && strings.Contains(line, " Pass: ") {
			proto := ""
			if end := strings.Index(line, "]"); end > 1 {
				proto = line[1:end]
			}
			user := extractBetween(line, " User: ", " Pass: ")
			pass := extractAfterLast(line, " Pass: ")
			if user != "" || pass != "" {
				results = append(results, ParsedCred{Username: user, Password: pass, Protocol: proto})
			}
		}
	}
	if len(results) > 0 {
		return results
	}

	// Prefixed multi-credential format (Sharp MX-2640): POP3 Username/Password, SMTP Username/Password
	for _, proto := range []string{"POP3", "SMTP"} {
		user := findPrefixedValue(lines, proto+" Username: ")
		pass := findPrefixedValue(lines, proto+" Password: ")
		hash := findPrefixedValue(lines, proto+" Hash: ")
		pw := pass
		if pw == "" {
			pw = hash
		}
		if user != "" && pw != "" {
			results = append(results, ParsedCred{Username: user, Password: pw, Protocol: proto})
		}
	}
	if len(results) > 0 {
		return results
	}

	// Standard line-based format (Ricoh DN/Password, Sharp MX-B468 Username/Password)
	user := ""
	pass := ""
	for _, line := range lines {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "DN: "):
			user = strings.TrimPrefix(line, "DN: ")
		case strings.HasPrefix(line, "Username: "):
			user = strings.TrimPrefix(line, "Username: ")
		case strings.HasPrefix(line, "User: "):
			user = strings.TrimPrefix(line, "User: ")
		case strings.HasPrefix(line, "Password: "):
			pass = strings.TrimPrefix(line, "Password: ")
		case strings.HasPrefix(line, "Pass: "):
			pass = strings.TrimPrefix(line, "Pass: ")
		}
	}
	if user != "" || pass != "" {
		results = append(results, ParsedCred{Username: user, Password: pass})
	}
	return results
}

// extractBetween extracts text between two markers in a line.
func extractBetween(line, start, end string) string {
	idx := strings.Index(line, start)
	if idx < 0 {
		return ""
	}
	rest := line[idx+len(start):]
	if endIdx := strings.Index(rest, end); endIdx >= 0 {
		return rest[:endIdx]
	}
	return rest
}

// extractAfterLast returns everything after the last occurrence of marker.
func extractAfterLast(line, marker string) string {
	idx := strings.LastIndex(line, marker)
	if idx < 0 {
		return ""
	}
	return line[idx+len(marker):]
}

// findPrefixedValue finds a line starting with prefix and returns the rest.
func findPrefixedValue(lines []string, prefix string) string {
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, prefix) {
			return line[len(prefix):]
		}
	}
	return ""
}

// GetDefaultCredInfo returns IPs with successful check results mapped to the
// port the check was performed on. Presence in the map means creds were found.
func GetDefaultCredInfo(workspaceID int64) (map[string]int, error) {
	rows, err := db.Query(
		`SELECT target, port FROM check_results
		 WHERE workspace_id = ? AND success = 1
		 ORDER BY checked_at DESC`,
		workspaceID)
	if err != nil {
		return nil, fmt.Errorf("get default cred info: %w", err)
	}
	defer rows.Close()

	info := make(map[string]int)
	for rows.Next() {
		var ip string
		var port int
		if err := rows.Scan(&ip, &port); err != nil {
			return nil, fmt.Errorf("scan check result row: %w", err)
		}
		// Keep the most recent (first due to ORDER BY DESC)
		if _, exists := info[ip]; !exists {
			info[ip] = port
		}
	}
	return info, rows.Err()
}
