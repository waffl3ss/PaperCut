package shell

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"

	"papercut/internal/cli"
	"papercut/internal/config"
	"papercut/internal/output"
	"papercut/internal/workspace"

	"github.com/chzyer/readline"
)

// Run starts the interactive REPL shell.
func Run(app *cli.App) error {
	rl, err := readline.NewEx(&readline.Config{
		Prompt:            buildPrompt(app),
		HistoryFile:       config.HistoryPath(),
		AutoComplete:      NewCompleter(app),
		InterruptPrompt:   "^C",
		EOFPrompt:         "exit",
		HistorySearchFold: true,
	})
	if err != nil {
		return fmt.Errorf("init readline: %w", err)
	}
	defer rl.Close()

	cli.PrintBanner()
	fmt.Println("  Type 'help' for available commands. Tab completion is available.")
	fmt.Println()

	for {
		rl.SetPrompt(buildPrompt(app))
		rl.Config.AutoComplete = NewCompleter(app)

		line, err := rl.Readline()
		if err == readline.ErrInterrupt {
			continue
		}
		if err == io.EOF {
			output.Info("Goodbye.")
			return nil
		}

		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		switch line {
		case "exit", "quit":
			output.Info("Goodbye.")
			return nil

		case "clear":
			clearScreen()
			continue

		case "banner":
			cli.PrintBanner()
			continue

		case "help":
			printHelp(app)
			continue
		}

		// Dispatch to cobra command tree
		if err := dispatch(app, line); err != nil {
			output.Warn("%v", err)
		}
	}
}

func buildPrompt(app *cli.App) string {
	ws := ""
	if app.ActiveWorkspace != nil {
		ws = fmt.Sprintf(" [\033[36m%s\033[0m]", app.ActiveWorkspace.Name)
	}
	mod := ""
	if app.ActiveModule != nil {
		info := app.ActiveModule.Info()
		catColor := "\033[32m" // green for SAFE
		if strings.EqualFold(info.Category, "UNSAFE") {
			catColor = "\033[31m" // red for UNSAFE
		}
		mod = fmt.Sprintf(" (\033[1m%s\033[0m) %s%s\033[0m", info.Name, catColor, info.Category)
	}
	return fmt.Sprintf("PaperCut%s%s > ", ws, mod)
}

func dispatch(app *cli.App, line string) error {
	args := splitArgs(line)
	if len(args) == 0 {
		return nil
	}

	// When a module is active, handle module-context commands
	if app.ActiveModule != nil {
		switch args[0] {
		case "set":
			return handleModuleSet(app, args)
		case "check":
			if len(args) == 1 {
				return handleModuleCheck(app)
			}
			// If check has flags (-t, -m), fall through to cobra for one-shot
		case "run":
			return handleModuleRun(app)
		}
	}

	root := cli.NewRootCmd(app)

	// Always add these interactive-only commands
	root.AddCommand(cli.NewUseCmd(app))
	root.AddCommand(cli.NewShowCmd(app))

	if app.ActiveModule != nil {
		root.AddCommand(cli.NewOptionsCmd(app))
		root.AddCommand(cli.NewBackCmd(app))
		// Note: `run` and bare `check` are intercepted above before cobra dispatch.
		// Do NOT add NewRunCmd or NewModuleCheckCmd here — NewModuleCheckCmd would
		// shadow newCheckCmd and break `check -t <target>` in module context.
		root.AddCommand(cli.NewSetCmd(app))
	} else {
		root.AddCommand(cli.NewSetCmd(app))
	}

	root.SetArgs(args)
	root.SilenceUsage = true
	root.SilenceErrors = true

	return root.Execute()
}

// handleModuleSet handles 'set' when a module is active.
// Uppercase keys → module options, lowercase → global options.
// Special key TARGET resolves a row number from scan results to RHOST.
func handleModuleSet(app *cli.App, args []string) error {
	if len(args) != 3 {
		return fmt.Errorf("usage: set <option> <value> (use quotes for values with spaces)")
	}
	key := args[1]
	val := args[2]

	// TARGET shortcut: resolve row number from results table to RHOST
	if strings.EqualFold(key, "TARGET") {
		if app.ActiveWorkspace == nil {
			return fmt.Errorf("no active workspace — cannot resolve TARGET")
		}
		n, err := strconv.Atoi(val)
		if err != nil {
			return fmt.Errorf("TARGET must be a number (row from results table)")
		}
		results, err := workspace.GetScanResults(app.ActiveWorkspace.ID, "")
		if err != nil {
			return fmt.Errorf("failed to get scan results: %w", err)
		}
		if n < 1 || n > len(results) {
			return fmt.Errorf("TARGET %d out of range (1-%d)", n, len(results))
		}
		target := results[n-1]
		if err := app.ActiveModule.SetOption("RHOST", target.IP); err != nil {
			return err
		}
		output.Info("TARGET %d => %s (%s %s)", n, target.IP, target.Manufacturer, target.Model)
		return nil
	}

	// If the key is all uppercase, it's a module option
	if isUpperCase(key) {
		if err := app.ActiveModule.SetOption(key, val); err != nil {
			return err
		}
		output.Info("%s => %s", key, val)
		return nil
	}

	// Otherwise delegate to global settings
	return cli.SetGlobalOption(app, key, val)
}

func handleModuleCheck(app *cli.App) error {
	rhost, err := app.ActiveModule.GetOption("RHOST")
	if err != nil || rhost.Value == "" {
		return fmt.Errorf("RHOST is not set")
	}
	var wsID int64
	if app.ActiveWorkspace != nil {
		wsID = app.ActiveWorkspace.ID
	}
	return cli.RunChecks(app, app.ActiveModule, rhost.Value, wsID)
}

func handleModuleRun(app *cli.App) error {
	rhost, err := app.ActiveModule.GetOption("RHOST")
	if err != nil || rhost.Value == "" {
		return fmt.Errorf("RHOST is not set")
	}
	var wsID int64
	if app.ActiveWorkspace != nil {
		wsID = app.ActiveWorkspace.ID
	}
	return cli.RunExploit(app, app.ActiveModule, rhost.Value, wsID)
}

func isUpperCase(s string) bool {
	return s == strings.ToUpper(s) && s != strings.ToLower(s)
}

// splitArgs does basic shell-like argument splitting, respecting quotes.
func splitArgs(line string) []string {
	var args []string
	var current strings.Builder
	inQuote := false
	quoteChar := byte(0)

	for i := 0; i < len(line); i++ {
		ch := line[i]
		switch {
		case inQuote:
			if ch == quoteChar {
				inQuote = false
			} else {
				current.WriteByte(ch)
			}
		case ch == '"' || ch == '\'':
			inQuote = true
			quoteChar = ch
		case ch == ' ' || ch == '\t':
			if current.Len() > 0 {
				args = append(args, current.String())
				current.Reset()
			}
		default:
			current.WriteByte(ch)
		}
	}
	if current.Len() > 0 {
		args = append(args, current.String())
	}

	return args
}

func clearScreen() {
	switch runtime.GOOS {
	case "windows":
		cmd := exec.Command("cmd", "/c", "cls")
		cmd.Stdout = os.Stdout
		cmd.Run()
	default:
		fmt.Print("\033[2J\033[H")
	}
}

func printHelp(app *cli.App) {
	help := `
  Scanning:
    scan -t <target>             Scan targets via PJL on port 9100
    results                      Show scan results for active workspace
    results --manufacturer <mfr> Filter results by manufacturer
    creds                        Show captured credentials for workspace

  Modules:
    search <term>                Search modules (case-insensitive)
    use <module|number>          Select a module (by name or search result #)
    options                      Show options for the active module
    set <OPTION> <value>         Set module option (UPPERCASE when module active)
    set TARGET <n>               Set RHOST from results table row number
    check                        Test default credentials (module context)
    run                          Execute the active module's exploit
    back                         Deselect the current module

  One-Shot (also works without 'use'):
    check -t <target> -m <mod>   Check for default credentials
    exploit -t <target> -m <mod> Run an exploitation module

  Workspace:
    workspace create <name>      Create a new workspace
    workspace use <name>         Switch to a workspace
    workspace list               List all workspaces
    workspace delete <name>      Delete a workspace
    workspace info               Show active workspace details

  Settings:
    set <option> <value>         Set global option (threads, timeout, rate, proxy)
    set proxy socks5://h:p       Route all traffic through SOCKS5 proxy
    set proxy socks4://h:p       Route all traffic through SOCKS4 proxy
    set proxy http://h:p         Route module HTTP traffic through HTTP proxy
    set proxy none               Disable proxy
    show                         Show current settings

  General:
    banner                       Display the banner
    clear                        Clear the screen
    help                         Show this help
    exit / quit                  Exit PaperCut
`
	fmt.Println(help)
}
