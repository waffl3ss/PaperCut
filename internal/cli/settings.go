package cli

import (
	"fmt"
	"strconv"
	"strings"

	"papercut/internal/modules"
	"papercut/internal/output"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/spf13/cobra"
)

// SetGlobalOption sets a global option by name. Exported for use by the shell's module-context set.
func SetGlobalOption(app *App, key, val string) error {
	switch key {
	case "threads":
		n, err := strconv.Atoi(val)
		if err != nil || n < 1 {
			return fmt.Errorf("threads must be a positive integer")
		}
		app.Options.Threads = n
		output.Info("threads => %d", n)

	case "timeout":
		n, err := strconv.Atoi(val)
		if err != nil || n < 1 {
			return fmt.Errorf("timeout must be a positive integer (seconds)")
		}
		app.Options.Timeout = n
		output.Info("timeout => %d", n)

	case "rate":
		n, err := strconv.Atoi(val)
		if err != nil || n < 0 {
			return fmt.Errorf("rate must be 0 (unlimited) or a positive integer (connections/sec)")
		}
		app.Options.Rate = n
		if n == 0 {
			output.Info("rate => unlimited")
		} else {
			output.Info("rate => %d/s", n)
		}

	case "proxy":
		if strings.EqualFold(val, "none") || strings.EqualFold(val, "off") || val == "" {
			app.Options.Proxy = ""
			output.Info("proxy => disabled")
		} else {
			normalized := modules.NormalizeProxy(val)
			// Validate scheme
			scheme := strings.SplitN(normalized, "://", 2)[0]
			switch scheme {
			case "socks5", "socks4", "socks4a", "http", "https":
				// valid
			default:
				return fmt.Errorf("unsupported proxy scheme %q — use socks5://, socks4://, http://, or https://", scheme)
			}
			app.Options.Proxy = normalized
			output.Info("proxy => %s", normalized)
			if scheme == "http" || scheme == "https" {
				output.Warn("HTTP proxies work for module exploits but NOT for PJL scanning (use socks4/socks5 for scans)")
			}
		}

	default:
		return fmt.Errorf("unknown option %q. Available: threads, timeout, rate, proxy", key)
	}

	return nil
}

func NewSetCmd(app *App) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "set [option] [value]",
		Short: "Set a global option (threads, timeout, rate, proxy)",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return SetGlobalOption(app, args[0], args[1])
		},
	}

	return cmd
}

func NewShowCmd(app *App) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "show",
		Short: "Show current settings",
		RunE: func(cmd *cobra.Command, args []string) error {
			t := table.NewWriter()
			t.SetStyle(table.StyleRounded)
			t.AppendHeader(table.Row{"Option", "Value"})
			t.AppendRow(table.Row{"threads", app.Options.Threads})
			t.AppendRow(table.Row{"timeout", fmt.Sprintf("%ds", app.Options.Timeout)})

			rate := "unlimited"
			if app.Options.Rate > 0 {
				rate = fmt.Sprintf("%d/s", app.Options.Rate)
			}
			t.AppendRow(table.Row{"rate", rate})

			proxy := app.Options.Proxy
			if proxy == "" {
				proxy = "(none)"
			}
			t.AppendRow(table.Row{"proxy", proxy})

			wsName := "(none)"
			if app.ActiveWorkspace != nil {
				wsName = app.ActiveWorkspace.Name
			}
			t.AppendRow(table.Row{"workspace", wsName})

			modName := "(none)"
			if app.ActiveModule != nil {
				modName = app.ActiveModule.Info().Name
			}
			t.AppendRow(table.Row{"module", modName})

			fmt.Println(t.Render())
			return nil
		},
	}

	return cmd
}
