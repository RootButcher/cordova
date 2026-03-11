// cordova/core/cmd/cordova-vault/root.go

package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"cordova/core/internal/config"
)

var (
	// cfgPath is the path to the YAML config file, set by the --config flag.
	cfgPath string

	// cfg is populated by PersistentPreRunE before any subcommand runs.
	cfg *config.Config
)

// rootCmd is the top-level cobra command for the cordova-vault daemon.
var rootCmd = &cobra.Command{
	Use:   "cordova-vault",
	Short: "Cordova vault daemon — manages the encrypted secret store",
	Long: "cordova-vault decrypts the vault file, loads secrets into memory, " +
		"and serves all requests over a Unix domain socket.",

	// PersistentPreRunE loads the config file before any subcommand executes.
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		// Skip config loading for commands that don't need it.
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

// execute is the entry point called from main. It runs the root command and
// exits with code 1 on error.
func execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().StringVar(&cfgPath, "config", "config.yaml", "path to config file")

	rootCmd.AddCommand(serveCmd)
	rootCmd.AddCommand(vaultCmd)
}
