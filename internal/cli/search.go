package cli

import (
	"fmt"
	"os"
	"strings"

	"papercut/internal/output"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jedib0t/go-pretty/v6/text"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

func newSearchCmd(app *App) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "search [term]",
		Short: "Search for modules (no args = list all)",
		Args:  cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			term := strings.Join(args, " ")
			results := app.Registry.Search(term)

			if len(results) == 0 {
				output.Info("No modules found matching %q", term)
				return nil
			}

			// Store results for 'use <number>' feature
			app.LastSearchResults = results

			t := table.NewWriter()
			style := table.StyleRounded
			style.Options.SeparateRows = true
			t.SetStyle(style)
			t.AppendHeader(table.Row{"#", "Name", "Category", "Manufacturer", "Models", "Description"})

			for i, m := range results {
				models := strings.Join(m.Models, ", ")
				t.AppendRow(table.Row{i + 1, m.Name, m.Category, m.Manufacturer, models, m.Description})
			}

			// Adapt Description and Models column widths to terminal size
			termWidth := getTermWidth()
			// Fixed columns: # (~3) + Name (~32) + Category (~10) + Manufacturer (~16) + borders (~7) + padding (~12)
			fixedWidth := 70
			flexWidth := termWidth - fixedWidth
			if flexWidth < 40 {
				flexWidth = 40
			}
			modelsMax := flexWidth / 3
			if modelsMax < 15 {
				modelsMax = 15
			}
			descMax := flexWidth - modelsMax
			if descMax < 20 {
				descMax = 20
			}
			t.SetColumnConfigs([]table.ColumnConfig{
				{Number: 5, WidthMax: modelsMax, WidthMaxEnforcer: text.WrapSoft},
				{Number: 6, WidthMax: descMax, WidthMaxEnforcer: text.WrapSoft},
			})

			fmt.Println(t.Render())
			return nil
		},
	}

	return cmd
}

// getTermWidth returns the current terminal width, or 120 as a fallback.
func getTermWidth() int {
	width, _, err := term.GetSize(int(os.Stdout.Fd()))
	if err != nil || width < 40 {
		return 120
	}
	return width
}
