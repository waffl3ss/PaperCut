package cli

import (
	"papercut/internal/config"
	"papercut/internal/modules"
	"papercut/internal/workspace"

	"github.com/spf13/cobra"
)

// App holds shared state accessible by all commands.
type App struct {
	Options           *config.Options
	ActiveWorkspace   *workspace.Workspace
	Registry          *modules.Registry
	ActiveModule      modules.ExploitModule
	LastSearchResults []modules.Module
}

// NewApp creates a new App with default settings.
func NewApp() *App {
	return &App{
		Options:  config.DefaultOptions(),
		Registry: modules.NewRegistry(),
	}
}

// NewRootCmd builds the cobra command tree. Used for both one-shot and interactive dispatch.
func NewRootCmd(app *App) *cobra.Command {
	root := &cobra.Command{
		Use:   "papercut",
		Short: "Printer Exploitation Framework",
		Long:  "PaperCut - A printer scanning and exploitation framework for penetration testing.",
	}

	// Global flags (used in one-shot mode).
	// Use current app values as defaults so interactive 'set' changes aren't overwritten
	// when the shell rebuilds the cobra tree each dispatch.
	root.PersistentFlags().IntVar(&app.Options.Threads, "threads", app.Options.Threads, "Number of concurrent workers")
	root.PersistentFlags().IntVar(&app.Options.Timeout, "timeout", app.Options.Timeout, "Connection timeout in seconds")
	root.PersistentFlags().IntVar(&app.Options.Rate, "rate", app.Options.Rate, "Max connections per second (0 = unlimited)")
	root.PersistentFlags().StringVar(&app.Options.Proxy, "proxy", app.Options.Proxy, "Proxy URL (socks4://, socks5://, http://)")

	// Add subcommands
	root.AddCommand(
		newScanCmd(app),
		newSearchCmd(app),
		newCheckCmd(app),
		newExploitCmd(app),
		newWorkspaceCmd(app),
		newResultsCmd(app),
		newCredsCmd(app),
	)

	return root
}
