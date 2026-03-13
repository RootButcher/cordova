// cordova/http/cmd/cordova-http/main.go

package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"cordova/http/server"
)

func main() {
	var cfg server.Config

	root := &cobra.Command{
		Use:   "cordova-http",
		Short: "HTTPS gateway for the cordova secrets daemon",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Printf("cordova-http listening on %s (socket: %s)\n", cfg.ListenAddr, cfg.SocketPath)
			if err := server.Run(cfg); err != nil {
				return fmt.Errorf("server: %w", err)
			}
			return nil
		},
	}

	root.Flags().StringVar(&cfg.SocketPath, "socket", socketDefault(), "Unix socket path")
	root.Flags().StringVar(&cfg.ListenAddr, "listen", ":8443", "HTTP listen address")
	root.Flags().StringVar(&cfg.TLSCert, "tls-cert", "", "Path to TLS certificate file")
	root.Flags().StringVar(&cfg.TLSKey, "tls-key", "", "Path to TLS private key file")

	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}

func socketDefault() string {
	if v := os.Getenv("CORDOVA_SOCKET"); v != "" {
		return v
	}
	return "/run/cordova/cordova.sock"
}
