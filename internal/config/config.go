package config

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// Options holds the global runtime settings.
type Options struct {
	Threads int
	Timeout int    // seconds
	Rate    int    // max connections per second, 0 = unlimited
	Proxy   string
}

// DefaultOptions returns sensible defaults.
func DefaultOptions() *Options {
	return &Options{
		Threads: 20,
		Timeout: 2,
		Rate:    0,
	}
}

var (
	dataDir  string
	initOnce sync.Once
)

// DataDir returns the path to ~/.PaperCut, creating it if needed.
func DataDir() string {
	initOnce.Do(func() {
		home, err := os.UserHomeDir()
		if err != nil {
			home = "."
		}
		dataDir = filepath.Join(home, ".PaperCut")
		if err := os.MkdirAll(dataDir, 0755); err != nil {
			fmt.Fprintf(os.Stderr, "[-] Failed to create data directory %s: %v\n", dataDir, err)
			os.Exit(1)
		}
	})
	return dataDir
}

// DBPath returns the full path to the SQLite database file.
func DBPath() string {
	return filepath.Join(DataDir(), "papercut.db")
}

// HistoryPath returns the full path to the readline history file.
func HistoryPath() string {
	return filepath.Join(DataDir(), "history")
}
