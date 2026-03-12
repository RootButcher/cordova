// cordova/admin/cli/root.go

package cli

import (
	"fmt"
	"os"

	"cordova/admin/client"
	"github.com/spf13/cobra"
)

var (
	socketPath string
	adminUser  string
	adminToken string
	Client     *client.Client
)

var rootCmd = &cobra.Command{
	Use:   "cordova-admin",
	Short: "Admin client for the cordova-vault daemon",
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		if socketPath == "" {
			socketPath = os.Getenv("CORDOVA_SOCKET")
		}
		if socketPath == "" {
			socketPath = "/run/cordova/cordova.sock"
		}
		if adminUser == "" {
			adminUser = os.Getenv("CORDOVA_USER")
		}
		if adminUser == "" {
			adminUser = "root"
		}
		if adminToken == "" {
			adminToken = os.Getenv("CORDOVA_TOKEN")
		}
		if adminToken == "" {
			return fmt.Errorf("token required: set --token or CORDOVA_TOKEN")
		}

		Client = client.New(socketPath, adminUser, adminToken)
		return nil
	},
}

// Execute runs the CLI and exits on error.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().StringVar(&socketPath, "socket", "", "cordova-vault socket path (or CORDOVA_SOCKET)")
	rootCmd.PersistentFlags().StringVar(&adminUser, "user", "", "username (or CORDOVA_USER, default: root)")
	rootCmd.PersistentFlags().StringVar(&adminToken, "token", "", "token secret (or CORDOVA_TOKEN)")

	rootCmd.AddCommand(keyCmd)
	rootCmd.AddCommand(tokenCmd)
	rootCmd.AddCommand(userCmd)
	rootCmd.AddCommand(socketCmd)
	rootCmd.AddCommand(statusCmd)
	rootCmd.AddCommand(sealCmd)
}