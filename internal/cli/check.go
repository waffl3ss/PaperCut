package cli

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"time"

	"papercut/internal/modules"
	"papercut/internal/output"
	"papercut/internal/target"
	"papercut/internal/workspace"

	"github.com/spf13/cobra"
)

// checkResult holds the outcome of a single check for serialized output.
type checkResult struct {
	ip      string
	success bool
	result  *modules.CheckResult
	err     error
}

func newCheckCmd(app *App) *cobra.Command {
	var targetStr string
	var moduleName string
	var wsName string

	cmd := &cobra.Command{
		Use:   "check",
		Short: "Check for default credentials using a module",
		RunE: func(cmd *cobra.Command, args []string) error {
			if targetStr == "" {
				return fmt.Errorf("target is required (-t)")
			}

			// Resolve module: explicit -m flag, or fall back to active module
			var mod modules.ExploitModule
			if moduleName != "" {
				m, ok := app.Registry.GetModule(moduleName)
				if !ok {
					return fmt.Errorf("module %q not found. Use 'search' to find available modules", moduleName)
				}
				mod = m
			} else if app.ActiveModule != nil {
				mod = app.ActiveModule
			} else {
				return fmt.Errorf("module is required (-m) or select one with 'use <module>'")
			}

			// Resolve workspace for storing results
			ws := app.ActiveWorkspace
			if wsName != "" {
				var err error
				ws, err = resolveOrCreateWorkspace(wsName)
				if err != nil {
					return err
				}
			}
			if ws == nil {
				return fmt.Errorf("no active workspace. Use 'workspace use <name>' or pass -w <name>")
			}

			return RunChecks(app, mod, targetStr, ws.ID)
		},
	}

	cmd.Flags().StringVarP(&targetStr, "target", "t", "", "Target IP, CIDR, or file path")
	cmd.Flags().StringVarP(&moduleName, "module", "m", "", "Module name")
	cmd.Flags().StringVarP(&wsName, "workspace", "w", "", "Workspace name (one-shot mode)")

	return cmd
}

// RunChecks runs a credential check against one or more targets using a concurrent worker pool.
// Exported so the interactive shell can call it for module-context `check`.
// If workspaceID > 0, results are stored in the database.
func RunChecks(app *App, mod modules.ExploitModule, targetStr string, workspaceID int64) error {
	stream, err := target.NewStream(targetStr)
	if err != nil {
		return fmt.Errorf("parse targets: %w", err)
	}

	info := mod.Info()
	workers := app.Options.Threads
	rate := app.Options.Rate

	// Snapshot options from the source module (everything except RHOST)
	optSnapshot := make(map[string]string)
	for _, opt := range mod.Options() {
		if opt.Name != "RHOST" {
			optSnapshot[opt.Name] = opt.Value
		}
	}

	// Global proxy supersedes module proxy (injected into snapshot, not the active module)
	if app.Options.Proxy != "" {
		optSnapshot["PROXY"] = app.Options.Proxy
	}

	// Check if we can create fresh module instances for concurrency
	_, hasFactory := app.Registry.NewModule(info.Name)
	if !hasFactory {
		output.Warn("No factory for module %s — falling back to sequential check", info.Name)
		workers = 1
	}

	// Single target: clean output without [1/1] noise
	if stream.Total == 1 {
		raw := <-stream.IPs
		ip, portOverride := splitHostPort(raw)

		var checkMod modules.ExploitModule
		if hasFactory {
			checkMod, _ = app.Registry.NewModule(info.Name)
			for k, v := range optSnapshot {
				checkMod.SetOption(k, v)
			}
		} else {
			checkMod = mod
		}
		checkMod.SetOption("RHOST", ip)
		if portOverride != "" {
			checkMod.SetOption("RPORT", portOverride)
		}

		result, err := checkMod.Check()
		if err != nil {
			return fmt.Errorf("check failed: %w", err)
		}

		// Store result in DB
		if workspaceID > 0 && result != nil {
			storeCheckResult(workspaceID, info.Name, ip, result)
		}

		if result == nil {
			output.Error("Check returned no result")
			return nil
		}

		if result.Success {
			pw := result.Password
			if pw == "" {
				pw = "(empty)"
			}
			output.Success("Default credentials valid: %s : %s", result.Username, pw)
			if result.Details != "" {
				output.Success("  %s", result.Details)
			}
		} else {
			output.Error("Default credentials not accepted")
			if result.Details != "" {
				output.Error("  %s", result.Details)
			}
		}
		return nil
	}

	// Multi-target: concurrent worker pool
	rateStr := ""
	if rate > 0 {
		rateStr = fmt.Sprintf(", rate: %d/s", rate)
	}
	output.Info("Checking %d target(s) with module %s (%d workers%s)",
		stream.Total, info.Name, workers, rateStr)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt)
	defer signal.Stop(sigCh)
	go func() {
		select {
		case <-sigCh:
			fmt.Println()
			output.Warn("Check interrupted")
			stream.Stop()
			cancel()
		case <-ctx.Done():
		}
	}()

	work := make(chan string, workers*2)
	resultCh := make(chan checkResult, workers*2)
	var wg sync.WaitGroup

	// Start workers
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			var workerMod modules.ExploitModule
			if hasFactory {
				workerMod, _ = app.Registry.NewModule(info.Name)
				for k, v := range optSnapshot {
					workerMod.SetOption(k, v)
				}
			} else {
				workerMod = mod
			}

			for raw := range work {
				select {
				case <-ctx.Done():
					return
				default:
				}

				ip, portOverride := splitHostPort(raw)
				workerMod.SetOption("RHOST", ip)
				if portOverride != "" {
					workerMod.SetOption("RPORT", portOverride)
				} else if defaultPort, ok := optSnapshot["RPORT"]; ok {
					workerMod.SetOption("RPORT", defaultPort)
				}

				result, err := workerMod.Check()
				resultCh <- checkResult{
					ip:      ip,
					success: result != nil && result.Success,
					result:  result,
					err:     err,
				}
			}
		}()
	}

	// Result collector — only print successes; failures are silent
	found := 0
	checked := 0
	var collectWG sync.WaitGroup
	collectWG.Add(1)
	go func() {
		defer collectWG.Done()
		for r := range resultCh {
			checked++

			// Store result in DB (both successes and failures)
			if workspaceID > 0 && r.result != nil {
				storeCheckResult(workspaceID, info.Name, r.ip, r.result)
			}

			if r.err != nil || !r.success {
				continue
			}
			found++
			pw := r.result.Password
			if pw == "" {
				pw = "(empty)"
			}
			output.Success("%s — default credentials valid: %s : %s", r.ip, r.result.Username, pw)
		}
	}()

	// Feed targets with optional rate limiting
	var ticker *time.Ticker
	if rate > 0 {
		interval := time.Second / time.Duration(rate)
		if interval <= 0 {
			interval = time.Microsecond
		}
		ticker = time.NewTicker(interval)
		defer ticker.Stop()
	}

	for ip := range stream.IPs {
		if ticker != nil {
			select {
			case <-ctx.Done():
				goto done
			case <-ticker.C:
			}
		}

		select {
		case <-ctx.Done():
			goto done
		case work <- ip:
		}
	}

done:
	close(work)
	wg.Wait()
	close(resultCh)
	collectWG.Wait()

	fmt.Println()
	output.Info("Check complete. %d of %d target(s) have default credentials.", found, checked)
	return nil
}

// storeCheckResult persists a check result to the database.
func storeCheckResult(workspaceID int64, moduleName, ip string, r *modules.CheckResult) {
	if err := workspace.InsertCheckResult(&workspace.CheckResult{
		WorkspaceID: workspaceID,
		ModuleName:  moduleName,
		Target:      ip,
		Port:        r.Port,
		Success:     r.Success,
		Username:    r.Username,
		Password:    r.Password,
		Details:     r.Details,
	}); err != nil {
		output.Warn("Failed to store check result: %v", err)
	}
}

// splitHostPort separates "ip:port" into host and port strings.
// Handles IPv6 bracket notation ([::1]:9100) and plain IPv4 (10.0.0.1:9100).
// Returns the original string and empty port if no port suffix is present.
func splitHostPort(target string) (host, port string) {
	// Try net.SplitHostPort first — handles IPv6 brackets correctly
	if h, p, err := net.SplitHostPort(target); err == nil {
		if _, err := strconv.Atoi(p); err == nil {
			return h, p
		}
	}
	// No port suffix or bare address — return as-is
	return target, ""
}
