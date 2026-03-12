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
	Short: "Initialise both secrets and users vaults",
	RunE:  runVaultInit,
}

func init() {
	vaultCmd.AddCommand(vaultInitCmd)
}

func runVaultInit(_ *cobra.Command, _ []string) error {
	c := cfg.Cordova
	kdf := vault.KDFParams{Time: c.KDF.Time, Memory: c.KDF.Memory, Threads: c.KDF.Threads}

	secretsPath := vaultFilePath(c.USB.MountBase, c.USB.VaultFilename)
	usersPath := vaultFilePath(c.USB.MountBase, c.UsersFilename)

	sv := vault.NewSecretsVault(secretsPath, kdf)
	uv := vault.NewUsersVault(usersPath, kdf)

	if sv.Exists() {
		return fmt.Errorf("secrets vault already exists at %s", secretsPath)
	}
	if uv.Exists() {
		return fmt.Errorf("users vault already exists at %s", usersPath)
	}

	if err := os.MkdirAll(dirOf(secretsPath), 0700); err != nil {
		return fmt.Errorf("creating vault directory: %w", err)
	}

	fmt.Print("new secrets passphrase: ")
	sPass1, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		return err
	}
	defer zeroBytes(sPass1)

	fmt.Print("confirm secrets passphrase: ")
	sPass2, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		return err
	}
	defer zeroBytes(sPass2)

	if string(sPass1) != string(sPass2) {
		return fmt.Errorf("secrets passphrases do not match")
	}

	fmt.Print("new users passphrase: ")
	uPass1, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		return err
	}
	defer zeroBytes(uPass1)

	fmt.Print("confirm users passphrase: ")
	uPass2, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		return err
	}
	defer zeroBytes(uPass2)

	if string(uPass1) != string(uPass2) {
		return fmt.Errorf("users passphrases do not match")
	}

	if err := sv.Init(sPass1); err != nil {
		return fmt.Errorf("initialising secrets vault: %w", err)
	}
	if err := uv.Init(uPass1); err != nil {
		return fmt.Errorf("initialising users vault: %w", err)
	}

	fmt.Printf("vault initialised at %s\n", secretsPath)
	fmt.Printf("users store initialised at %s\n", usersPath)
	fmt.Println("root user created (no tokens — use serve --gen-root to bootstrap)")
	return nil
}