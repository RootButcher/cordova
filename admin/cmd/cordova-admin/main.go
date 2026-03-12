// cordova/admin/cmd/cordova-admin/main.go

package main

import (
	"fmt"
	"os"

	"cordova/admin/cli"
	"cordova/admin/tui"
)

func main() {
	if len(os.Args) == 1 {
		socketPath := os.Getenv("CORDOVA_SOCKET")
		if socketPath == "" {
			socketPath = "/run/cordova/cordova.sock"
		}
		username := os.Getenv("CORDOVA_USER")
		// CORDOVA_TOKEN is optional — if unset the TUI shows an auth screen.
		token := os.Getenv("CORDOVA_TOKEN")

		if err := tui.Run(socketPath, username, token); err != nil {
			_, _ = fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	cli.Execute()
}