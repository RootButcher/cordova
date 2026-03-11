// cordova/admin/cmd/cordova-admin/main.go
//
// cordova-admin is the admin client for the cordova-vault daemon. When invoked
// with no arguments it launches an interactive TUI. When invoked with
// subcommand arguments (e.g. "key list") it runs in non-interactive CLI mode.

package main

import (
	"fmt"
	"os"

	"cordova/admin/cli"
	"cordova/admin/tui"
)

func main() {
	// With no arguments, launch the interactive TUI.
	if len(os.Args) == 1 {
		socketPath := os.Getenv("CORDOVA_SOCKET")
		if socketPath == "" {
			socketPath = "/run/cordova/cordova.sock"
		}
		// CORDOVA_TOKEN is optional — if unset the TUI shows an auth screen.
		token := os.Getenv("CORDOVA_TOKEN")

		if err := tui.Run(socketPath, token); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}

	// Otherwise hand off to the cobra CLI.
	cli.Execute()
}
