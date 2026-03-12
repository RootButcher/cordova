// cordova/core/cmd/cordova-vault/serve.go

package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"cordova/core/internal/audit"
	"cordova/core/internal/config"
	"cordova/core/internal/socket"
	"cordova/core/internal/store"
	"cordova/core/internal/vault"
)

var genRoot bool

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Unseal both vaults and start the socket server",
	Long: "Unseals the secrets and users vaults and begins serving requests.\n" +
		"Pass --gen-root to emit a one-time ephemeral token for the root user.",
	RunE: runServe,
}

func init() {
	serveCmd.Flags().BoolVar(&genRoot, "gen-root", false,
		"create a temporary unrestricted socket and ephemeral root token for bootstrapping")
}

func runServe(_ *cobra.Command, _ []string) error {
	c := cfg.Cordova

	if err := os.MkdirAll(dirOf(c.Audit.LogPath), 0700); err != nil {
		return fmt.Errorf("creating audit log dir: %w", err)
	}
	auditLog, err := audit.New(c.Audit.LogPath)
	if err != nil {
		return fmt.Errorf("opening audit log: %w", err)
	}
	defer func() { _ = auditLog.Close() }()

	kdf := vault.KDFParams{Time: c.KDF.Time, Memory: c.KDF.Memory, Threads: c.KDF.Threads}

	secretsVault := vault.NewSecretsVault(
		vaultFilePath(c.USB.MountBase, c.USB.VaultFilename), kdf)
	usersVault := vault.NewUsersVault(
		vaultFilePath(c.USB.MountBase, c.UsersFilename), kdf)

	if !secretsVault.Exists() {
		return fmt.Errorf("secrets vault not found at %s — run: cordova-vault vault init", secretsVault.Path())
	}
	if !usersVault.Exists() {
		return fmt.Errorf("users vault not found at %s — run: cordova-vault vault init", usersVault.Path())
	}

	secStore := store.NewSecretsStore()
	defer secStore.Zero()
	userStore := store.NewUserStore()
	defer userStore.Zero()

	_, _ = fmt.Fprint(os.Stderr, "secrets passphrase: ")
	secretsPass, err := term.ReadPassword(int(os.Stdin.Fd()))
	_, _ = fmt.Fprintln(os.Stderr)
	if err != nil {
		return fmt.Errorf("reading secrets passphrase: %w", err)
	}

	_, _ = fmt.Fprint(os.Stderr, "users passphrase: ")
	usersPass, err := term.ReadPassword(int(os.Stdin.Fd()))
	_, _ = fmt.Fprintln(os.Stderr)
	if err != nil {
		zeroBytes(secretsPass)
		return fmt.Errorf("reading users passphrase: %w", err)
	}

	secState, err := secretsVault.Unseal(secretsPass)
	if err != nil {
		zeroBytes(secretsPass)
		zeroBytes(usersPass)
		return fmt.Errorf("unsealing secrets vault: %w", err)
	}
	secStore.Load(secState)

	usersState, err := usersVault.Unseal(usersPass)
	if err != nil {
		zeroBytes(secretsPass)
		zeroBytes(usersPass)
		secStore.Zero()
		return fmt.Errorf("unsealing users vault: %w", err)
	}
	userStore.Load(usersState)

	auditLog.Log(audit.Entry{Event: audit.EventVaultUnseal})
	slog.Info("vaults unsealed")

	socketsConfig, err := config.LoadSockets(c.SocketsConfig)
	if err != nil {
		zeroBytes(secretsPass)
		zeroBytes(usersPass)
		return fmt.Errorf("loading sockets config: %w", err)
	}

	srv := socket.NewServer(
		c.SocketsConfig,
		socketsConfig,
		secStore, userStore,
		secretsVault, usersVault,
		auditLog,
		secretsPass, usersPass,
	)
	secretsPass = nil
	usersPass = nil

	if err := srv.Start(); err != nil {
		return fmt.Errorf("starting socket server: %w", err)
	}

	if genRoot {
		if err := startGenRoot(srv, userStore, c); err != nil {
			srv.Stop()
			return err
		}
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
	secStore.Zero()
	userStore.Zero()
	slog.Info("vaults sealed — goodbye")
	return nil
}

// startGenRoot creates a temporary unrestricted socket and an ephemeral token
// on the root user, printing both to stderr for the operator.
func startGenRoot(srv *socket.Server, userStore *store.UserStore, c config.CordovaConfig) error {
	rawID := make([]byte, 4)
	if _, err := rand.Read(rawID); err != nil {
		return fmt.Errorf("generating gen-root socket id: %w", err)
	}
	socketDir := dirOf(c.Audit.LogPath)
	socketPath := socketDir + "/root-" + hex.EncodeToString(rawID) + ".sock"

	const tokenName = "gen-root"
	secret, err := userStore.AddToken("root", tokenName, "ephemeral root token", vault.EphemeralExpiry())
	if err != nil {
		return fmt.Errorf("generating ephemeral root token: %w", err)
	}

	entry := config.SocketEntry{
		Name:  "gen-root",
		Path:  socketPath,
		Scope: config.SocketScope{Unrestricted: true},
	}
	if err := srv.AddEphemeralSocket(entry, "root", tokenName); err != nil {
		return fmt.Errorf("starting gen-root socket: %w", err)
	}

	_, _ = fmt.Fprintf(os.Stderr, "root-socket: %s\n", socketPath)
	_, _ = fmt.Fprintf(os.Stderr, "root-token:  %s\n", secret)
	return nil
}