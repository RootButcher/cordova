// cordova/core/cmd/cordova-vault/main.go
//
// cordova-vault is the core daemon. It decrypts the vault file, loads secrets
// into memory, emits an ephemeral root token, and serves all requests over a
// Unix domain socket.

package main

func main() {
	execute()
}
