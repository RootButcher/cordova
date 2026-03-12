// cordova/core/internal/vault/vault.go

package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"golang.org/x/crypto/argon2"
)

const (
	magic          = "CRDV"
	currentVersion = byte(0x01)
)

const (
	MagicSize    = len(magic)
	VersionSize  = 1
	SaltSize     = 32
	NonceSize    = 12
	AESKeySize   = 32
	HeaderSize   = MagicSize + VersionSize + SaltSize + NonceSize
	MinVaultSize = HeaderSize + 1 + 16
)

// KDFParams holds Argon2id key derivation parameters.
type KDFParams struct {
	Time    uint32
	Memory  uint32
	Threads uint8
}

// EphemeralExpiry returns the sentinel *time.Time used to mark a token as
// ephemeral (process-scoped, never written to disk).
//
// The zero time (0001-01-01 00:00:00 UTC) is used as the sentinel because:
//   - nil already means "persistent / no expiry"
//   - A real TTL is always a future timestamp, never year 1
//   - The zero value is unambiguous and easy to detect with time.Time.IsZero()
func EphemeralExpiry() *time.Time {
	t := time.Time{}
	return &t
}

// Token is a credential owned by a User. It carries no permissions — those
// are derived from the owning User and the connected socket's scope.
type Token struct {
	Name        string     `json:"name"`
	Hash        string     `json:"hash"`
	Description string     `json:"description"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	LastUsed    *time.Time `json:"last_used,omitempty"`
}

// IsPersistent reports whether the token never expires.
func (t *Token) IsPersistent() bool { return t.ExpiresAt == nil }

// IsEphemeral reports whether the token is process-scoped (never persisted).
func (t *Token) IsEphemeral() bool {
	return t.ExpiresAt != nil && t.ExpiresAt.IsZero()
}

// IsExpired reports whether a TTL token has passed its expiry time.
func (t *Token) IsExpired() bool {
	return t.ExpiresAt != nil && !t.ExpiresAt.IsZero() && time.Now().UTC().After(*t.ExpiresAt)
}

// User is a node in the user tree. The root user has an empty Parent field.
// nil Namespaces, Keys, or Sockets means unrestricted (root only by default).
type User struct {
	Name       string    `json:"name"`
	Parent     string    `json:"parent"`
	Admin      bool      `json:"admin"`
	Namespaces []string  `json:"namespaces,omitempty"`
	Keys       []string  `json:"keys,omitempty"`
	Writable   bool      `json:"writable"`
	Sockets    []string  `json:"sockets,omitempty"`
	Tokens     []Token   `json:"tokens,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
}

// SecretsState holds all secret key-value pairs managed by the secrets vault.
type SecretsState struct {
	Keys map[string]string `json:"keys"`
}

// Zero overwrites and clears all secret values.
func (s *SecretsState) Zero() {
	for k, v := range s.Keys {
		b := []byte(v)
		for i := range b {
			b[i] = 0
		}
		delete(s.Keys, k)
	}
	s.Keys = nil
}

// UsersState holds the full user tree managed by the users vault.
type UsersState struct {
	Users []User `json:"users"`
}

// SecretsVault manages the encrypted secrets file (cordova.vault).
type SecretsVault struct {
	path   string
	params KDFParams
}

// NewSecretsVault creates a SecretsVault for the given path and KDF params.
func NewSecretsVault(path string, params KDFParams) *SecretsVault {
	return &SecretsVault{path: path, params: params}
}

// Unseal decrypts and returns the SecretsState.
func (v *SecretsVault) Unseal(passphrase []byte) (*SecretsState, error) {
	var state SecretsState
	if err := unsealFile(v.path, v.params, passphrase, &state); err != nil {
		return nil, err
	}
	if state.Keys == nil {
		state.Keys = make(map[string]string)
	}
	return &state, nil
}

// Seal encrypts and atomically writes the SecretsState to disk.
func (v *SecretsVault) Seal(state *SecretsState, passphrase []byte) error {
	return sealFile(v.path, v.params, passphrase, state)
}

// Init creates a new empty secrets vault. Returns an error if it already exists.
func (v *SecretsVault) Init(passphrase []byte) error {
	if _, err := os.Stat(v.path); err == nil {
		return fmt.Errorf("secrets vault already exists at %s", v.path)
	}
	return v.Seal(&SecretsState{Keys: make(map[string]string)}, passphrase)
}

// Exists reports whether the vault file exists on disk.
func (v *SecretsVault) Exists() bool {
	_, err := os.Stat(v.path)
	return err == nil
}

// Path returns the vault file path.
func (v *SecretsVault) Path() string { return v.path }

// UsersVault manages the encrypted users file (cordova.users).
type UsersVault struct {
	path   string
	params KDFParams
}

// NewUsersVault creates a UsersVault for the given path and KDF params.
func NewUsersVault(path string, params KDFParams) *UsersVault {
	return &UsersVault{path: path, params: params}
}

// Unseal decrypts and returns the UsersState.
func (v *UsersVault) Unseal(passphrase []byte) (*UsersState, error) {
	var state UsersState
	if err := unsealFile(v.path, v.params, passphrase, &state); err != nil {
		return nil, err
	}
	if state.Users == nil {
		state.Users = []User{}
	}
	return &state, nil
}

// Seal encrypts and atomically writes the UsersState to disk.
func (v *UsersVault) Seal(state *UsersState, passphrase []byte) error {
	return sealFile(v.path, v.params, passphrase, state)
}

// Init creates a new users vault seeded with only the root user.
// Returns an error if the file already exists.
func (v *UsersVault) Init(passphrase []byte) error {
	if _, err := os.Stat(v.path); err == nil {
		return fmt.Errorf("users vault already exists at %s", v.path)
	}
	state := &UsersState{
		Users: []User{{
			Name:      "root",
			Parent:    "",
			Admin:     true,
			CreatedAt: time.Now().UTC(),
		}},
	}
	return v.Seal(state, passphrase)
}

// Exists reports whether the vault file exists on disk.
func (v *UsersVault) Exists() bool {
	_, err := os.Stat(v.path)
	return err == nil
}

// Path returns the vault file path.
func (v *UsersVault) Path() string { return v.path }

// ── Shared crypto primitives ──────────────────────────────────────────────────

// unsealFile reads, decrypts, and JSON-unmarshals a vault file into dst.
func unsealFile(path string, params KDFParams, passphrase []byte, dst any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("reading vault: %w", err)
	}
	if len(data) < MinVaultSize {
		return fmt.Errorf("vault file too short (%d bytes, minimum %d): corrupt or empty",
			len(data), MinVaultSize)
	}

	magicEnd := MagicSize
	versionEnd := magicEnd + VersionSize
	saltEnd := versionEnd + SaltSize
	nonceEnd := saltEnd + NonceSize

	if string(data[:magicEnd]) != magic {
		return errors.New("invalid vault magic — not a cordova vault file")
	}
	if data[magicEnd] != currentVersion {
		return fmt.Errorf("unsupported vault version 0x%02x — expected 0x%02x",
			data[magicEnd], currentVersion)
	}

	salt := data[versionEnd:saltEnd]
	nonce := data[saltEnd:nonceEnd]
	ciphertext := data[nonceEnd:]

	key := argon2.IDKey(passphrase, salt, params.Time, params.Memory, params.Threads, AESKeySize)
	defer zeroBytes(key)

	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("creating AES cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("creating GCM: %w", err)
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		// Do not expose whether the failure is a bad passphrase or corrupt file.
		return errors.New("decryption failed — wrong passphrase or corrupt vault")
	}
	defer zeroBytes(plaintext)

	if err := json.Unmarshal(plaintext, dst); err != nil {
		return fmt.Errorf("parsing vault contents: %w", err)
	}
	return nil
}

// sealFile JSON-marshals src, encrypts it with a fresh salt and nonce, and
// atomically writes the result to path via a .tmp rename.
func sealFile(path string, params KDFParams, passphrase []byte, src any) error {
	plaintext, err := json.Marshal(src)
	if err != nil {
		return fmt.Errorf("serialising vault: %w", err)
	}
	defer zeroBytes(plaintext)

	salt := make([]byte, SaltSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return fmt.Errorf("generating salt: %w", err)
	}
	nonce := make([]byte, NonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return fmt.Errorf("generating nonce: %w", err)
	}

	key := argon2.IDKey(passphrase, salt, params.Time, params.Memory, params.Threads, AESKeySize)
	defer zeroBytes(key)

	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("creating AES cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("creating GCM: %w", err)
	}

	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)

	out := make([]byte, 0, HeaderSize+len(ciphertext))
	out = append(out, []byte(magic)...)
	out = append(out, currentVersion)
	out = append(out, salt...)
	out = append(out, nonce...)
	out = append(out, ciphertext...)

	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, out, 0600); err != nil {
		return fmt.Errorf("writing vault tmp file: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("renaming vault into place: %w", err)
	}
	return nil
}

func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}