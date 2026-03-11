// cordova/core/cmd/cordova-vault/serve.go

package main

import (
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"cordova/core/internal/audit"
	"cordova/core/internal/socket"
	"cordova/core/internal/store"
	"cordova/core/internal/vault"
)

var genRoot bool

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Unseal the vault and start the socket server",
	Long: "Unseals the vault and begins serving requests over the Unix socket.\n" +
		"Pass --gen-root to emit a one-time root token for initial bootstrapping.",
	RunE: runServe,
}

func init() {
	serveCmd.Flags().BoolVar(&genRoot, "gen-root", false,
		"generate a one-time ephemeral root token (for bootstrapping only)")
}

func runServe(cmd *cobra.Command, args []string) error {
	c := cfg.Cordova
	if err := os.MkdirAll(dirOf(c.Audit.LogPath), 0700); err != nil {
		return fmt.Errorf("creating audit log dir: %w", err)
	}
	auditLog, err := audit.New(c.Audit.LogPath)
	if err != nil {
		return fmt.Errorf("opening audit log: %w", err)
	}
	defer auditLog.Close()

	if err := os.MkdirAll(dirOf(c.RootSocket), 0700); err != nil {
		return fmt.Errorf("creating socket dir: %w", err)
	}

	v := vault.New(
		vaultFilePath(c.USB.MountBase, c.USB.VaultFilename),
		vault.KDFParams{Time: c.KDF.Time, Memory: c.KDF.Memory, Threads: c.KDF.Threads},
	)
	if !v.Exists() {
		return fmt.Errorf("vault not found at %s — run: cordova-vault vault init", v.Path())
	}

	s := store.New()
	defer s.Zero()

	fmt.Fprint(os.Stderr, "passphrase: ")
	passphrase, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return fmt.Errorf("reading passphrase: %w", err)
	}

	state, err := v.Unseal(passphrase)
	if err != nil {
		zeroBytes(passphrase)
		return fmt.Errorf("unsealing vault: %w", err)
	}
	s.Load(state)
	auditLog.Log(audit.Entry{Event: audit.EventVaultUnseal})
	slog.Info("vault unsealed")

	if genRoot {
		secret, err := s.AddToken("root", "ephemeral root token", vault.EphemeralExpiry(), nil, nil, nil, false)
		if err != nil {
			zeroBytes(passphrase)
			return fmt.Errorf("generating root token: %w", err)
		}
		fmt.Fprintf(os.Stderr, "root-token: %s\n", secret)
	}
	srv := socket.NewServer(c.RootSocket, s, v, auditLog, passphrase)
	passphrase = nil

	if err := srv.Start(); err != nil {
		return fmt.Errorf("starting socket server: %w", err)
	}
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	select {
	case sig := <-sigCh:
		slog.Info("signal received, shutting down", "signal", sig)
	case <-srv.SealRequested():
		slog.Warn("seal triggered via socket — shutting down")
	}
	srv.Stop()
	auditLog.Log(audit.Entry{Event: audit.EventVaultSeal})
	s.Zero()
	slog.Info("vault sealed — goodbye")

	return nil
}
