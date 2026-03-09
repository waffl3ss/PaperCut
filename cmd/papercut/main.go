package main

import (
	"fmt"
	"os"

	"papercut/internal/cli"
	"papercut/internal/modules/safe"
	"papercut/internal/modules/unsafe"
	"papercut/internal/shell"
	"papercut/internal/workspace"
)

func main() {
	// Initialize database
	if err := workspace.InitDB(); err != nil {
		fmt.Fprintf(os.Stderr, "[!] Failed to initialize database: %v\n", err)
		os.Exit(1)
	}
	defer workspace.CloseDB()

	app := cli.NewApp()

	// Register all modules
	safe.RegisterAll(app.Registry)
	unsafe.RegisterAll(app.Registry)

	// If arguments were provided, run in one-shot CLI mode
	if len(os.Args) > 1 {
		root := cli.NewRootCmd(app)
		root.SetArgs(os.Args[1:])
		if err := root.Execute(); err != nil {
			os.Exit(1)
		}
		return
	}

	// No arguments — launch interactive shell
	if err := shell.Run(app); err != nil {
		fmt.Fprintf(os.Stderr, "[!] Shell error: %v\n", err)
		os.Exit(1)
	}
}
