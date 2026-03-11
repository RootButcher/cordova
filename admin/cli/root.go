// cordova/admin/cli/root.go
//
// Package cli implements the cobra-based command-line interface for
// cordova-admin. It is invoked when the binary is called with subcommand
// arguments. For interactive use with no arguments, cordova-admin launches
// the bubbletea TUI instead.

package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"cordova/admin/client"
)

var (
	// socketPath is resolved from --socket flag then CORDOVA_SOCKET env var.
	socketPath string

	// adminToken is resolved from --token flag then CORDOVA_TOKEN env var.
	adminToken string

	// Client is the shared IPC client used by all subcommands. It is
	// initialised in PersistentPreRunE after flags and env vars are resolved.
	Client *client.Client
)

// rootCmd is the top-level cobra command for cordova-admin CLI mode.
var rootCmd = &cobra.Command{
	Use:   "cordova-admin",
	Short: "Admin client for the cordova-vault daemon",

	// PersistentPreRunE resolves the socket path and token, then constructs the
	// shared IPC client before any subcommand runs.
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		if socketPath == "" {
			socketPath = os.Getenv("CORDOVA_SOCKET")
		}
		if socketPath == "" {
			socketPath = "/run/cordova/cordova.sock"
		}

		if adminToken == "" {
			adminToken = os.Getenv("CORDOVA_TOKEN")
		}
		if adminToken == "" {
			return fmt.Errorf("token required: set --token or CORDOVA_TOKEN")
		}

		Client = client.New(socketPath, adminToken)
		return nil
	},
}

// Execute runs the cobra root command. Called from main when CLI args are present.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().StringVar(&socketPath, "socket", "", "cordova-vault socket path (or CORDOVA_SOCKET)")
	rootCmd.PersistentFlags().StringVar(&adminToken, "token", "", "admin or root token (or CORDOVA_TOKEN)")

	rootCmd.AddCommand(keyCmd)
	rootCmd.AddCommand(tokenCmd)
	rootCmd.AddCommand(statusCmd)
	rootCmd.AddCommand(sealCmd)
}
