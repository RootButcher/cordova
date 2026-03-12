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

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err) //TODO log error
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
