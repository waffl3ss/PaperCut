package cli

import (
	"fmt"
	"strconv"
	"strings"

	"papercut/internal/output"
	"papercut/internal/workspace"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/spf13/cobra"
)

func newResultsCmd(app *App) *cobra.Command {
	var manufacturer string
	var wsName string
	var setRhost bool
	var credsOnly bool

	cmd := &cobra.Command{
		Use:   "results",
		Short: "Display scan results for the active workspace",
		RunE: func(cmd *cobra.Command, args []string) error {
			ws := app.ActiveWorkspace
			if wsName != "" {
				var err error
				ws, err = workspace.GetByName(wsName)
				if err != nil {
					if err == workspace.ErrNotFound {
						return fmt.Errorf("workspace %q not found", wsName)
					}
					return err
				}
			}
			if ws == nil {
				return fmt.Errorf("no active workspace. Use 'workspace use <name>' or pass -w <name>")
			}

			results, err := workspace.GetScanResults(ws.ID, manufacturer)
			if err != nil {
				return fmt.Errorf("query results: %w", err)
			}

			if len(results) == 0 {
				if manufacturer != "" {
					output.Info("No results matching manufacturer %q in workspace %q", manufacturer, ws.Name)
				} else {
					output.Info("No scan results in workspace %q. Run 'scan' first.", ws.Name)
				}
				return nil
			}

			// Fetch IPs with successful default cred checks (IP → check port)
			credInfo, _ := workspace.GetDefaultCredInfo(ws.ID)
			if credInfo == nil {
				credInfo = make(map[string]int)
			}

			// Apply --creds filter
			if credsOnly {
				var filtered []*workspace.ScanResult
				for _, r := range results {
					if _, ok := credInfo[r.IP]; ok {
						filtered = append(filtered, r)
					}
				}
				results = filtered
				if len(results) == 0 {
					output.Info("No hosts with valid credentials in workspace %q", ws.Name)
					return nil
				}
			}

			t := table.NewWriter()
			t.SetStyle(table.StyleRounded)
			t.AppendHeader(table.Row{"#", "IP", "Port", "Manufacturer", "Model", "Creds", "Scanned At"})

			for i, r := range results {
				cred := ""
				if port, ok := credInfo[r.IP]; ok {
					if port > 0 {
						cred = fmt.Sprintf("\u2713 :%d", port)
					} else {
						cred = "\u2713"
					}
				}
				t.AppendRow(table.Row{
					i + 1,
					r.IP,
					r.Port,
					r.Manufacturer,
					r.Model,
					cred,
					r.ScannedAt.Format("2006-01-02 15:04:05"),
				})
			}

			output.Info("Scan results for workspace %q:", ws.Name)
			fmt.Println(t.Render())

			// -R flag: set RHOST on the active module from displayed results.
			// Include :port suffix when the check port differs from the module's RPORT
			// so that check/run hits the correct service port per host.
			if setRhost {
				if app.ActiveModule == nil {
					output.Warn("No active module — cannot set RHOST. Use 'use <module>' first.")
					return nil
				}

				modulePort := ""
				if rport, err := app.ActiveModule.GetOption("RPORT"); err == nil {
					modulePort = rport.Value
				}

				var targets []string
				for _, r := range results {
					entry := r.IP
					if checkPort, ok := credInfo[r.IP]; ok && checkPort > 0 {
						if strconv.Itoa(checkPort) != modulePort {
							entry = fmt.Sprintf("%s:%d", r.IP, checkPort)
						}
					}
					targets = append(targets, entry)
				}
				rhostVal := strings.Join(targets, ",")
				if err := app.ActiveModule.SetOption("RHOST", rhostVal); err != nil {
					return fmt.Errorf("set RHOST: %w", err)
				}
				output.Info("RHOST set to %d target(s)", len(targets))
			}

			return nil
		},
	}

	cmd.Flags().StringVarP(&manufacturer, "manufacturer", "M", "", "Filter by manufacturer (case-insensitive)")
	cmd.Flags().StringVarP(&wsName, "workspace", "w", "", "Workspace name (one-shot mode)")
	cmd.Flags().BoolVarP(&setRhost, "set-rhost", "R", false, "Set RHOST on active module from displayed results")
	cmd.Flags().BoolVarP(&credsOnly, "creds", "c", false, "Show only hosts with valid credentials")

	return cmd
}
