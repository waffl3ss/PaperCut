package cli

import (
	"fmt"

	"papercut/internal/output"
	"papercut/internal/workspace"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/spf13/cobra"
)

func newWorkspaceCmd(app *App) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "workspace",
		Short: "Manage workspaces",
	}

	cmd.AddCommand(
		newWorkspaceCreateCmd(app),
		newWorkspaceUseCmd(app),
		newWorkspaceListCmd(app),
		newWorkspaceDeleteCmd(app),
		newWorkspaceInfoCmd(app),
	)

	return cmd
}

func newWorkspaceCreateCmd(app *App) *cobra.Command {
	return &cobra.Command{
		Use:   "create [name]",
		Short: "Create a new workspace",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			ws, err := workspace.Create(name)
			if err != nil {
				return fmt.Errorf("failed to create workspace: %w", err)
			}
			app.ActiveWorkspace = ws
			output.Success("Workspace %q created and set as active", ws.Name)
			return nil
		},
	}
}

func newWorkspaceUseCmd(app *App) *cobra.Command {
	return &cobra.Command{
		Use:   "use [name]",
		Short: "Switch to a workspace",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			ws, err := workspace.GetByName(name)
			if err != nil {
				if err == workspace.ErrNotFound {
					return fmt.Errorf("workspace %q not found", name)
				}
				return err
			}
			app.ActiveWorkspace = ws
			output.Info("Switched to workspace %q", ws.Name)
			return nil
		},
	}
}

func newWorkspaceListCmd(app *App) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List all workspaces",
		RunE: func(cmd *cobra.Command, args []string) error {
			workspaces, err := workspace.List()
			if err != nil {
				return fmt.Errorf("list workspaces: %w", err)
			}

			if len(workspaces) == 0 {
				output.Info("No workspaces found. Use 'workspace create <name>' to create one.")
				return nil
			}

			t := table.NewWriter()
			t.SetStyle(table.StyleRounded)
			t.AppendHeader(table.Row{"#", "Name", "Devices", "Created"})

			for i, ws := range workspaces {
				count, _ := workspace.ScanResultCount(ws.ID)
				active := ""
				if app.ActiveWorkspace != nil && app.ActiveWorkspace.ID == ws.ID {
					active = " *"
				}
				t.AppendRow(table.Row{
					i + 1,
					ws.Name + active,
					count,
					ws.CreatedAt.Format("2006-01-02 15:04"),
				})
			}

			fmt.Println(t.Render())
			return nil
		},
	}
}

func newWorkspaceDeleteCmd(app *App) *cobra.Command {
	return &cobra.Command{
		Use:   "delete [name]",
		Short: "Delete a workspace and all its data",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			if err := workspace.Delete(name); err != nil {
				return fmt.Errorf("delete workspace: %w", err)
			}
			// Clear active workspace if it was the deleted one
			if app.ActiveWorkspace != nil && app.ActiveWorkspace.Name == name {
				app.ActiveWorkspace = nil
			}
			output.Success("Workspace %q deleted", name)
			return nil
		},
	}
}

func newWorkspaceInfoCmd(app *App) *cobra.Command {
	return &cobra.Command{
		Use:   "info",
		Short: "Show details about the active workspace",
		RunE: func(cmd *cobra.Command, args []string) error {
			ws := app.ActiveWorkspace
			if ws == nil {
				output.Info("No active workspace")
				return nil
			}

			count, _ := workspace.ScanResultCount(ws.ID)
			manufacturers, _ := workspace.GetManufacturers(ws.ID)

			fmt.Printf("  Name:          %s\n", ws.Name)
			fmt.Printf("  Created:       %s\n", ws.CreatedAt.Format("2006-01-02 15:04:05"))
			fmt.Printf("  Devices Found: %d\n", count)
			if len(manufacturers) > 0 {
				fmt.Printf("  Manufacturers: %v\n", manufacturers)
			}
			return nil
		},
	}
}
