package cli

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"time"

	"papercut/internal/output"
	"papercut/internal/scanner"
	"papercut/internal/target"
	"papercut/internal/workspace"

	"github.com/schollz/progressbar/v3"
	"github.com/spf13/cobra"
)

func newScanCmd(app *App) *cobra.Command {
	var targetStr string
	var wsName string

	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Scan targets on port 9100 via PJL to identify printers",
		RunE: func(cmd *cobra.Command, args []string) error {
			if targetStr == "" {
				return fmt.Errorf("target is required (-t)")
			}

			// Resolve workspace
			ws := app.ActiveWorkspace
			if wsName != "" {
				var err error
				ws, err = resolveOrCreateWorkspace(wsName)
				if err != nil {
					return err
				}
			}
			if ws == nil {
				return fmt.Errorf("no active workspace. Use 'workspace create <name>' and 'workspace use <name>' first, or pass -w <name>")
			}

			// Stream targets lazily (no full expansion into memory)
			stream, err := target.NewStream(targetStr)
			if err != nil {
				return fmt.Errorf("parse targets: %w", err)
			}

			// Print large network recommendations for anything bigger than a /16
			if stream.Total > 65534 {
				if !promptLargeNetwork(stream.Total, app.Options.Threads, app.Options.Timeout) {
					stream.Stop()
					output.Info("Scan cancelled.")
					return nil
				}
			}

			rateStr := ""
			if app.Options.Rate > 0 {
				rateStr = fmt.Sprintf(", rate: %d/s", app.Options.Rate)
			}
			proxyStr := ""
			if app.Options.Proxy != "" {
				proxyStr = fmt.Sprintf(", proxy: %s", app.Options.Proxy)
				// Warn if using HTTP proxy for raw TCP scanning
				if strings.HasPrefix(app.Options.Proxy, "http://") || strings.HasPrefix(app.Options.Proxy, "https://") {
					output.Warn("HTTP proxies cannot tunnel raw TCP — PJL scan requires socks4:// or socks5://")
					stream.Stop()
					return nil
				}
			}
			output.Info("Scanning %d target(s) with %d workers (timeout: %ds%s%s)",
				stream.Total, app.Options.Threads, app.Options.Timeout, rateStr, proxyStr)

			// Progress bar
			bar := progressbar.NewOptions(stream.Total,
				progressbar.OptionSetDescription("[*] Scanning"),
				progressbar.OptionSetWriter(os.Stderr),
				progressbar.OptionShowCount(),
				progressbar.OptionShowIts(),
				progressbar.OptionSetItsString("hosts"),
				progressbar.OptionClearOnFinish(),
			)

			found := 0

			cfg := &scanner.ScanConfig{
				Targets:     stream.IPs,
				Port:        9100,
				Workers:     app.Options.Threads,
				Timeout:     time.Duration(app.Options.Timeout) * time.Second,
				Rate:        app.Options.Rate,
				Proxy:       app.Options.Proxy,
				WorkspaceID: ws.ID,
				OnResult: func(r *scanner.PJLResult) {
					found++
					fmt.Fprint(os.Stderr, "\033[2K\r")
					output.Success("%s -- %s (%s)", r.IP, r.Model, r.Manufacturer)
					bar.Add(1)
				},
				OnError: func(ip string) {
					bar.Add(1)
				},
			}

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			// Handle Ctrl+C gracefully
			sigCh := make(chan os.Signal, 1)
			signal.Notify(sigCh, os.Interrupt)
			defer signal.Stop(sigCh)
			go func() {
				select {
				case <-sigCh:
					fmt.Println()
					output.Warn("Scan interrupted")
					stream.Stop()
					cancel()
				case <-ctx.Done():
				}
			}()

			_, err = scanner.Run(ctx, cfg)
			bar.Finish()

			if err != nil {
				return fmt.Errorf("scan: %w", err)
			}

			fmt.Println()
			output.Info("Scan complete. Found %d printer(s) out of %d target(s).", found, stream.Total)
			return nil
		},
	}

	cmd.Flags().StringVarP(&targetStr, "target", "t", "", "Target IP, CIDR, or file path")
	cmd.Flags().StringVarP(&wsName, "workspace", "w", "", "Workspace name (one-shot mode)")

	return cmd
}

func promptLargeNetwork(total, currentThreads, currentTimeout int) bool {
	output.Warn("Large network detected. Estimated scan times at your current settings and recommended alternatives:")
	fmt.Println()

	type preset struct {
		label   string
		threads int
		timeout int
	}

	presets := []preset{
		{"Current settings", currentThreads, currentTimeout},
		{"Recommended", 100, 2},
		{"Aggressive", 200, 1},
		{"Max speed", 500, 1},
	}

	fmt.Printf("    %-20s %-10s %-10s %-15s %s\n", "Profile", "Threads", "Timeout", "Hosts/sec", "Est. Time")
	fmt.Printf("    %-20s %-10s %-10s %-15s %s\n", "-------", "-------", "-------", "---------", "---------")

	for _, p := range presets {
		hostsPerSec := float64(p.threads) / float64(p.timeout)
		seconds := float64(total) / hostsPerSec
		timeoutStr := fmt.Sprintf("%ds", p.timeout)
		hostsStr := fmt.Sprintf("~%.0f", hostsPerSec)
		fmt.Printf("    %-20s %-10d %-10s %-15s %s\n",
			p.label, p.threads, timeoutStr, hostsStr, formatDuration(seconds))
	}

	fmt.Println()
	output.Info("Tune with: set threads <n> / set timeout <n>")
	fmt.Print("\nContinue? [y/N] ")

	var response string
	fmt.Scanln(&response)
	response = strings.TrimSpace(strings.ToLower(response))
	return response == "y" || response == "yes"
}

func formatDuration(seconds float64) string {
	if seconds < 60 {
		return fmt.Sprintf("%.0fs", seconds)
	}
	if seconds < 3600 {
		return fmt.Sprintf("%.0fm", seconds/60)
	}
	hours := seconds / 3600
	if hours < 24 {
		return fmt.Sprintf("%.1fh", hours)
	}
	return fmt.Sprintf("%.1f days", hours/24)
}

func resolveOrCreateWorkspace(name string) (*workspace.Workspace, error) {
	ws, err := workspace.GetByName(name)
	if err == nil {
		return ws, nil
	}
	if err != workspace.ErrNotFound {
		return nil, fmt.Errorf("lookup workspace %q: %w", name, err)
	}
	ws, err = workspace.Create(name)
	if err != nil {
		return nil, fmt.Errorf("create workspace %q: %w", name, err)
	}
	output.Info("Created workspace %q", name)
	return ws, nil
}
