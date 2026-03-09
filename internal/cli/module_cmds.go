package cli

import (
	"fmt"
	"strconv"
	"strings"

	"papercut/internal/output"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jedib0t/go-pretty/v6/text"
	"github.com/spf13/cobra"
)

// NewUseCmd creates the 'use' command for selecting a module interactively.
// Accepts a module name or a number from the last search results.
func NewUseCmd(app *App) *cobra.Command {
	return &cobra.Command{
		Use:   "use [module|number]",
		Short: "Select a module for interactive use",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]

			// Check if the argument is a number (from search results)
			if n, err := strconv.Atoi(name); err == nil {
				if len(app.LastSearchResults) == 0 {
					return fmt.Errorf("no previous search results. Run 'search <term>' first")
				}
				if n < 1 || n > len(app.LastSearchResults) {
					return fmt.Errorf("invalid selection %d (valid range: 1-%d)", n, len(app.LastSearchResults))
				}
				name = app.LastSearchResults[n-1].Name
			}

			mod, ok := app.Registry.GetModule(name)
			if !ok {
				return fmt.Errorf("module %q not found. Use 'search' to find modules", name)
			}
			app.ActiveModule = mod
			info := mod.Info()
			output.Info("Using module: %s", info.Name)
			output.Info("%s", info.Description)
			output.Info("Category: %s | Manufacturer: %s", info.Category, info.Manufacturer)
			if len(info.Models) > 0 {
				output.Info("Models: %s", strings.Join(info.Models, ", "))
			}
			return nil
		},
	}
}

// NewBackCmd creates the 'back' command for deselecting the current module.
func NewBackCmd(app *App) *cobra.Command {
	return &cobra.Command{
		Use:   "back",
		Short: "Deselect the current module",
		RunE: func(cmd *cobra.Command, args []string) error {
			if app.ActiveModule == nil {
				return fmt.Errorf("no module is currently selected")
			}
			output.Info("Deselected module: %s", app.ActiveModule.Info().Name)
			app.ActiveModule = nil
			return nil
		},
	}
}

// NewOptionsCmd creates the 'options' command for displaying module options.
func NewOptionsCmd(app *App) *cobra.Command {
	return &cobra.Command{
		Use:   "options",
		Short: "Show options for the active module",
		RunE: func(cmd *cobra.Command, args []string) error {
			if app.ActiveModule == nil {
				return fmt.Errorf("no module selected. Use 'use <module>' first")
			}

			mod := app.ActiveModule
			info := mod.Info()
			opts := mod.Options()

			fmt.Printf("\n  Module: %s\n", info.Name)
			fmt.Printf("  %s\n", info.Description)
			fmt.Printf("  Category: %s | Manufacturer: %s\n", info.Category, info.Manufacturer)
			if len(info.Models) > 0 {
				fmt.Printf("  Models: %s\n", strings.Join(info.Models, ", "))
			}
			fmt.Println()

			t := table.NewWriter()
			t.SetStyle(table.StyleRounded)
			t.AppendHeader(table.Row{"Name", "Current", "Required", "Description"})

			for _, o := range opts {
				req := "no"
				if o.Required {
					req = "yes"
				}
				val := o.Value
				t.AppendRow(table.Row{o.Name, val, req, o.Description})
			}

			// Cap the Current column so long comma-separated target lists
			// don't blow out the table width.
			t.SetColumnConfigs([]table.ColumnConfig{
				{Number: 2, WidthMax: 40, WidthMaxEnforcer: text.WrapSoft},
			})

			fmt.Println(t.Render())
			return nil
		},
	}
}

