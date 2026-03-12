// cordova/core/cmd/cordova-vault/vault.go

package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"cordova/core/internal/vault"
)

var vaultCmd = &cobra.Command{
	Use:   "vault",
	Short: "Vault lifecycle commands (init, etc.)",
}
var vaultInitCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialise a new empty vault",
	RunE:  runVaultInit,
}

func init() {
	vaultCmd.AddCommand(vaultInitCmd)
}

// TODO Claude explain unused params
func runVaultInit(cmd *cobra.Command, args []string) error {
	c := cfg.Cordova
	vaultPath := vaultFilePath(c.USB.MountBase, c.USB.VaultFilename)

	v := vault.New(vaultPath, vault.KDFParams{
		Time:    c.KDF.Time,
		Memory:  c.KDF.Memory,
		Threads: c.KDF.Threads,
	})

	if v.Exists() {
		return fmt.Errorf("vault already exists at %s", vaultPath)
	}

	if err := os.MkdirAll(dirOf(vaultPath), 0700); err != nil {
		return fmt.Errorf("creating vault directory: %w", err)
	}

	fmt.Print("new passphrase: ")
	pass1, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		return err
	}
	defer zeroBytes(pass1)

	fmt.Print("confirm passphrase: ")
	pass2, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		return err
	}
	defer zeroBytes(pass2)

	if string(pass1) != string(pass2) {
		return fmt.Errorf("passphrases do not match")
	}

	if err := v.Init(pass1); err != nil {
		return fmt.Errorf("initialising vault: %w", err)
	}

	fmt.Printf("vault initialised at %s\n", vaultPath)
	return nil
}
