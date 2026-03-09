package workspace

import (
	"database/sql"
	"fmt"

	_ "modernc.org/sqlite"

	"papercut/internal/config"
)

var db *sql.DB

// InitDB opens (or creates) the SQLite database and runs migrations.
func InitDB() error {
	var err error
	db, err = sql.Open("sqlite", config.DBPath())
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}

	// Enable WAL mode and foreign keys
	for _, pragma := range []string{
		"PRAGMA journal_mode=WAL",
		"PRAGMA foreign_keys=ON",
	} {
		if _, err := db.Exec(pragma); err != nil {
			return fmt.Errorf("exec %s: %w", pragma, err)
		}
	}

	return migrate()
}

// CloseDB cleanly shuts down the database connection.
func CloseDB() {
	if db != nil {
		db.Close()
	}
}

func migrate() error {
	schema := `
	CREATE TABLE IF NOT EXISTS workspaces (
		id         INTEGER PRIMARY KEY AUTOINCREMENT,
		name       TEXT UNIQUE NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS scan_results (
		id             INTEGER PRIMARY KEY AUTOINCREMENT,
		workspace_id   INTEGER NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
		ip             TEXT NOT NULL,
		port           INTEGER NOT NULL DEFAULT 9100,
		manufacturer   TEXT,
		model          TEXT,
		pjl_raw_id     TEXT,
		pjl_raw_status TEXT,
		hostname       TEXT,
		scanned_at     DATETIME DEFAULT CURRENT_TIMESTAMP,
		UNIQUE(workspace_id, ip, port)
	);

	CREATE TABLE IF NOT EXISTS check_results (
		id           INTEGER PRIMARY KEY AUTOINCREMENT,
		workspace_id INTEGER NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
		module_name  TEXT NOT NULL,
		target       TEXT NOT NULL,
		port         INTEGER NOT NULL,
		success      BOOLEAN NOT NULL,
		username     TEXT,
		password     TEXT,
		details      TEXT,
		checked_at   DATETIME DEFAULT CURRENT_TIMESTAMP,
		UNIQUE(workspace_id, module_name, target, port)
	);

	CREATE TABLE IF NOT EXISTS exploit_results (
		id           INTEGER PRIMARY KEY AUTOINCREMENT,
		workspace_id INTEGER NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
		module_name  TEXT NOT NULL,
		target       TEXT NOT NULL,
		port         INTEGER NOT NULL,
		success      BOOLEAN NOT NULL,
		username     TEXT,
		password     TEXT,
		details      TEXT,
		data         TEXT,
		exploited_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		UNIQUE(workspace_id, module_name, target, port)
	);

	CREATE INDEX IF NOT EXISTS idx_scan_results_workspace ON scan_results(workspace_id);
	CREATE INDEX IF NOT EXISTS idx_check_results_workspace ON check_results(workspace_id);
	CREATE INDEX IF NOT EXISTS idx_exploit_results_workspace ON exploit_results(workspace_id);
	`
	_, err := db.Exec(schema)
	if err != nil {
		return fmt.Errorf("migrate schema: %w", err)
	}
	return nil
}
