package cli

import (
	"fmt"

	"papercut/internal/output"
	"papercut/internal/workspace"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/spf13/cobra"
)

func newCredsCmd(app *App) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "creds",
		Short: "Show captured credentials for the active workspace",
		RunE: func(cmd *cobra.Command, args []string) error {
			ws := app.ActiveWorkspace
			if ws == nil {
				return fmt.Errorf("no active workspace. Use 'workspace use <name>' first")
			}

			creds, err := workspace.GetCredentials(ws.ID)
			if err != nil {
				return fmt.Errorf("get credentials: %w", err)
			}

			if len(creds) == 0 {
				output.Info("No credentials captured in workspace %q", ws.Name)
				return nil
			}

			t := table.NewWriter()
			t.SetStyle(table.StyleRounded)
			t.AppendHeader(table.Row{"Host", "Port", "Username", "Password", "Module", "Protocol"})

			for _, c := range creds {
				pw := c.Password
				if pw == "" {
					pw = "(empty)"
				}
				proto := c.Protocol
				if proto == "" {
					proto = "-"
				}
				t.AppendRow(table.Row{c.Target, c.Port, c.Username, pw, c.ModuleName, proto})
			}

			fmt.Println(t.Render())
			return nil
		},
	}

	return cmd
}
