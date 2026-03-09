package shell

import (
	"os"
	"path/filepath"
	"strings"

	"papercut/internal/cli"
	"papercut/internal/workspace"

	"github.com/chzyer/readline"
)

// ShellCompleter wraps PrefixCompleter with flag-aware completion for commands
// that accept multiple flags in any order (check, exploit, results).
// PrefixCompleter's tree structure only supports flags in a fixed order because
// dynamic items are leaf nodes — it can't recurse past a dynamic value to offer
// the next flag. This wrapper intercepts those commands and provides order-
// independent flag + value completion, delegating everything else to the tree.
type ShellCompleter struct {
	prefix *readline.PrefixCompleter
	app    *cli.App
}

// Do implements readline.AutoCompleter.
func (c *ShellCompleter) Do(line []rune, pos int) ([][]rune, int) {
	lineStr := string(line[:pos])
	trimmed := strings.TrimLeft(lineStr, " \t")

	switch {
	case c.app.ActiveModule == nil && strings.HasPrefix(trimmed, "check "):
		return c.completeFlagged(trimmed[len("check "):], c.checkFlags())
	case c.app.ActiveModule == nil && strings.HasPrefix(trimmed, "exploit "):
		return c.completeFlagged(trimmed[len("exploit "):], c.exploitFlags())
	case strings.HasPrefix(trimmed, "results "):
		return c.completeFlagged(trimmed[len("results "):], c.resultsFlags())
	}

	return c.prefix.Do(line, pos)
}

// flagDef describes a single flag for flag-aware completion.
type flagDef struct {
	takesValue bool                  // true if the flag consumes the next token as a value
	completer  func(string) []string // returns candidates given a partial value; nil = no completion
}

func (c *ShellCompleter) checkFlags() map[string]flagDef {
	return map[string]flagDef{
		"-t": {true, listFiles},
		"-m": {true, func(string) []string { return c.app.Registry.Names() }},
		"-w": {true, func(string) []string {
			names, _ := workspace.ListNames()
			return names
		}},
	}
}

func (c *ShellCompleter) exploitFlags() map[string]flagDef {
	return map[string]flagDef{
		"-t": {true, listFiles},
		"-m": {true, func(string) []string { return c.app.Registry.Names() }},
		"-l": {true, nil},
		"-p": {true, nil},
		"-w": {true, func(string) []string {
			names, _ := workspace.ListNames()
			return names
		}},
	}
}

func (c *ShellCompleter) resultsFlags() map[string]flagDef {
	mfrCompleter := func(string) []string {
		if c.app.ActiveWorkspace == nil {
			return nil
		}
		mfrs, _ := workspace.GetManufacturers(c.app.ActiveWorkspace.ID)
		var out []string
		for _, m := range mfrs {
			out = append(out, strings.ToLower(m))
		}
		return out
	}
	return map[string]flagDef{
		"--manufacturer": {true, mfrCompleter},
		"-M":             {true, mfrCompleter},
		"-R":             {false, nil},
		"-c":             {false, nil},
		"-w": {true, func(string) []string {
			names, _ := workspace.ListNames()
			return names
		}},
	}
}

// completeFlagged provides order-independent flag completion.
// rest is everything after the command name (e.g. for "check -t foo", rest = "-t foo").
func (c *ShellCompleter) completeFlagged(rest string, flags map[string]flagDef) ([][]rune, int) {
	tokens := strings.Fields(rest)
	endsWithSpace := rest == "" || strings.HasSuffix(rest, " ")

	// Split into fully-typed tokens and the partial token at the cursor
	completed := tokens
	partial := ""
	if !endsWithSpace && len(tokens) > 0 {
		completed = tokens[:len(tokens)-1]
		partial = tokens[len(tokens)-1]
	}

	// Walk completed tokens to track used flags and detect a pending value
	usedFlags := map[string]bool{}
	expectingValueFor := ""
	for _, tok := range completed {
		if expectingValueFor != "" {
			expectingValueFor = ""
			continue
		}
		if def, ok := flags[tok]; ok {
			usedFlags[tok] = true
			if def.takesValue {
				expectingValueFor = tok
			}
		}
	}

	// Last completed flag still expects a value — complete that value
	if expectingValueFor != "" {
		def := flags[expectingValueFor]
		if def.completer != nil {
			return toCompletions(def.completer(partial), partial)
		}
		return nil, 0
	}

	// No pending value — suggest unused flags
	var suggestions []string
	for f := range flags {
		if !usedFlags[f] {
			suggestions = append(suggestions, f)
		}
	}
	return toCompletions(suggestions, partial)
}

// toCompletions filters suggestions by prefix and returns readline-compatible completions.
func toCompletions(suggestions []string, prefix string) ([][]rune, int) {
	var result [][]rune
	for _, s := range suggestions {
		if strings.HasPrefix(s, prefix) {
			result = append(result, []rune(s[len(prefix):]))
		}
	}
	if len(result) == 0 {
		return nil, 0
	}
	return result, len(prefix)
}

// NewCompleter builds a ShellCompleter. Multi-flag commands (check, exploit,
// results) are handled by the custom flag-aware logic; everything else uses
// the PrefixCompleter tree.
func NewCompleter(app *cli.App) *ShellCompleter {
	items := []readline.PrefixCompleterInterface{
		readline.PcItem("scan",
			readline.PcItem("-t",
				readline.PcItemDynamic(fileCompleter()),
			),
			readline.PcItem("--target",
				readline.PcItemDynamic(fileCompleter()),
			),
		),
		readline.PcItem("search",
			readline.PcItemDynamic(moduleNameCompleter(app)),
		),
		readline.PcItem("use",
			readline.PcItemDynamic(moduleNameCompleter(app)),
		),
		readline.PcItem("workspace",
			readline.PcItem("create"),
			readline.PcItem("use",
				readline.PcItemDynamic(workspaceNameCompleter()),
			),
			readline.PcItem("list"),
			readline.PcItem("delete",
				readline.PcItemDynamic(workspaceNameCompleter()),
			),
			readline.PcItem("info"),
		),
		// results: flag completion handled by ShellCompleter.Do()
		readline.PcItem("results"),
		readline.PcItem("creds"),
		readline.PcItem("show"),
		readline.PcItem("banner"),
		readline.PcItem("clear"),
		readline.PcItem("help"),
		readline.PcItem("exit"),
		readline.PcItem("quit"),
	}

	if app.ActiveModule != nil {
		// Module-context commands
		items = append(items,
			readline.PcItem("options"),
			readline.PcItem("run"),
			readline.PcItem("check",
				readline.PcItem("-t",
					readline.PcItemDynamic(fileCompleter()),
				),
			),
			readline.PcItem("back"),
			readline.PcItem("set",
				readline.PcItemDynamic(moduleOptionCompleter(app)),
			),
		)
	} else {
		// Global-only set; check/exploit flag completion handled by ShellCompleter.Do()
		items = append(items,
			readline.PcItem("set",
				readline.PcItem("threads"),
				readline.PcItem("timeout"),
				readline.PcItem("rate"),
				readline.PcItem("proxy"),
			),
			readline.PcItem("check"),
			readline.PcItem("exploit"),
		)
	}

	return &ShellCompleter{
		prefix: readline.NewPrefixCompleter(items...),
		app:    app,
	}
}

func workspaceNameCompleter() func(string) []string {
	return func(line string) []string {
		names, err := workspace.ListNames()
		if err != nil {
			return nil
		}
		return names
	}
}

func moduleNameCompleter(app *cli.App) func(string) []string {
	return func(line string) []string {
		return app.Registry.Names()
	}
}

func moduleOptionCompleter(app *cli.App) func(string) []string {
	return func(line string) []string {
		var names []string
		if app.ActiveModule != nil {
			names = append(names, "TARGET")
			for _, o := range app.ActiveModule.Options() {
				names = append(names, o.Name)
			}
		}
		// Also include global options
		names = append(names, "threads", "timeout", "rate", "proxy")
		return names
	}
}

// fileCompleter wraps listFiles for use with PrefixCompleter's PcItemDynamic.
// The callback receives the full original line; we extract the partial path
// from the last token (or empty if the line ends with a space).
func fileCompleter() func(string) []string {
	return func(line string) []string {
		partial := ""
		if !strings.HasSuffix(line, " ") {
			parts := strings.Fields(line)
			if len(parts) > 0 {
				partial = parts[len(parts)-1]
			}
		}
		return listFiles(partial)
	}
}

// listFiles returns file and directory paths matching the given partial prefix.
// Used by both the PrefixCompleter fileCompleter and the flag-aware completer.
func listFiles(partial string) []string {
	dir := "."
	prefix := ""
	if partial != "" {
		if info, err := os.Stat(partial); err == nil && info.IsDir() {
			dir = partial
			prefix = partial
			if !strings.HasSuffix(prefix, string(os.PathSeparator)) {
				prefix += string(os.PathSeparator)
			}
		} else {
			dir = filepath.Dir(partial)
			prefix = partial
		}
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}

	var matches []string
	for _, e := range entries {
		name := e.Name()
		// Skip hidden files unless they're explicitly typing a dot prefix
		if strings.HasPrefix(name, ".") && !strings.HasPrefix(filepath.Base(partial), ".") {
			continue
		}

		var full string
		if dir == "." && partial == "" {
			full = name
		} else if strings.HasSuffix(prefix, string(os.PathSeparator)) {
			full = prefix + name
		} else {
			full = filepath.Join(filepath.Dir(prefix), name)
		}

		// Add trailing separator for directories so they can keep tabbing
		if e.IsDir() {
			full += string(os.PathSeparator)
		}

		if partial == "" || strings.HasPrefix(full, partial) {
			matches = append(matches, full)
		}
	}

	return matches
}
