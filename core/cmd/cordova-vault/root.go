// cordova/core/cmd/cordova-vault/root.go

package main

import (
	"fmt"
	"os"

	"cordova/core/internal/config"
	"github.com/spf13/cobra"
)

var (
	cfgPath string
	cfg     *config.Config
)
var rootCmd = &cobra.Command{
	Use:   "cordova-vault",
	Short: "Cordova vault daemon — manages the encrypted secret store",
	Long: "cordova-vault decrypts the vault file, loads secrets into memory, " +
		"and serves all requests over a Unix domain socket.",

	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		skip := map[string]bool{"help": true, "completion": true}
		if skip[cmd.Name()] {
			return nil
		}
		var err error
		cfg, err = config.Load(cfgPath)
		if err != nil {
			return fmt.Errorf("loading config from %s: %w", cfgPath, err)
		}
		return nil
	},
}

func execute() {
	if err := rootCmd.Execute(); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func init() {
	rootCmd.PersistentFlags().StringVar(&cfgPath, "config", "config.yaml", "path to config file")

	rootCmd.AddCommand(serveCmd)
	rootCmd.AddCommand(vaultCmd)
}
