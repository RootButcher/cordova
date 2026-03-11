// cordova/core/internal/vault/vault.go

// Package vault handles AES-256-GCM encryption and decryption of the vault
// file, and defines the data types that live inside it. All sensitive material
// is kept in memory only while the vault is unsealed; callers must call
// State.Zero() when finished to clear key material from the heap.
package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"time"

	"golang.org/x/crypto/argon2"
)

// File format constants — all sizes in bytes.
const (
	MagicSize   = 4  // "CRDV"
	VersionSize = 1  // format version byte
	SaltSize    = 32 // Argon2id salt
	NonceSize   = 12 // AES-GCM nonce
	AESKeySize  = 32 // AES-256 derived key length

	// HeaderSize is the total size of the unencrypted file header.
	HeaderSize = MagicSize + VersionSize + SaltSize + NonceSize

	// MinVaultSize is the smallest valid vault file:
	// header + minimum AES-GCM ciphertext (1 byte) + GCM tag (16 bytes).
	MinVaultSize = HeaderSize + 1 + 16
)

const (
	magic          = "CRDV"
	currentVersion = byte(0x01)
)

// KDFParams holds Argon2id tuning parameters used to derive the AES key from
// the vault passphrase. Tune for the target hardware (default: Pi Zero 2W).
type KDFParams struct {
	Time    uint32
	Memory  uint32
	Threads uint8
}

// DefaultKDFParams returns safe KDF defaults tuned for a Raspberry Pi Zero 2W.
func DefaultKDFParams() KDFParams {
	return KDFParams{Time: 1, Memory: 65536, Threads: 2}
}

// TokenRole describes what level of access a token provides.
type TokenRole string

const (
	// RoleAdmin grants full, unrestricted access to the vault — equivalent to
	// the root token. Admin tokens are persistent and stored in the vault.
	RoleAdmin TokenRole = "admin"

	// RoleAccess grants scoped read/write access constrained by CIDRs,
	// namespaces, and explicit key names. Reserved for future cordova-http and
	// cordova-ssh consumers. Admin operations require RoleAdmin or root.
	RoleAccess TokenRole = "access"
)

// EphemeralExpiry returns the sentinel *time.Time used to mark a token as
// ephemeral (process-scoped, never written to disk).
//
// The zero time (0001-01-01 00:00:00 UTC) is used as the sentinel because:
//   - nil already means "persistent / no expiry"
//   - A real TTL is always a future timestamp, never year 1
//   - The zero value is unambiguous and easy to detect with time.Time.IsZero()
//
// Ephemeral tokens are filtered out by store.Snapshot before any vault write,
// so this value should never appear in a vault file.
func EphemeralExpiry() *time.Time {
	t := time.Time{} // zero value — the sentinel for ephemeral
	return &t
}

// Token represents an access credential. ExpiresAt controls persistence:
//
//   - nil         → persistent (no expiry, written to disk)
//   - zero time   → ephemeral (process-scoped only, never written to disk)
//   - future time → TTL (written to disk, rejected and deleted on first use after expiry)
type Token struct {
	// Name is the human-readable slug identifier for this token, e.g. "ops-box".
	// It is used for revocation and display. Must be unique within the vault.
	Name string `json:"name"`

	// Hash is the hex-encoded SHA-256 hash of the secret bearer credential.
	// The raw credential is never stored; only this hash is kept on disk.
	Hash string `json:"hash"`

	// Description is a human-readable label assigned at creation time,
	// e.g. "ops workstation" or "truenas fetch job".
	Description string `json:"description"`

	// Role determines the level of access this token grants.
	// Must be RoleAdmin or RoleAccess.
	Role TokenRole `json:"role"`

	// ExpiresAt controls the token lifetime and persistence. See the Token
	// type comment for the three-state semantics (nil / zero / future).
	ExpiresAt *time.Time `json:"expires_at,omitempty"`

	// CIDRs restricts which source IP addresses may present this token.
	// Only enforced for RoleAccess tokens by future HTTP/SSH consumers;
	// admin tokens are not restricted by source address.
	CIDRs []string `json:"cidrs,omitempty"`

	// Namespaces allows access to all keys whose name begins with the given
	// namespace prefix (e.g. "prod" matches "prod/db-pass"). Only meaningful
	// for RoleAccess tokens.
	Namespaces []string `json:"namespaces,omitempty"`

	// Keys lists explicit key names this token may access in addition to any
	// namespace-matched keys. Only meaningful for RoleAccess tokens.
	Keys []string `json:"keys,omitempty"`

	// Writable permits the token to set key values, not just read them.
	// Only meaningful for RoleAccess tokens.
	Writable bool `json:"writable,omitempty"`

	// CreatedAt is the UTC timestamp when this token was created.
	CreatedAt time.Time `json:"created_at"`

	// LastUsed is updated each time the token successfully authenticates.
	// It is nil until the token is used for the first time.
	LastUsed *time.Time `json:"last_used,omitempty"`
}

// IsPersistent reports whether the token has no expiry and will be written to disk.
func (t *Token) IsPersistent() bool {
	return t.ExpiresAt == nil
}

// IsEphemeral reports whether the token is process-scoped and must never be
// written to disk. Detected via the zero-time sentinel; see EphemeralExpiry.
func (t *Token) IsEphemeral() bool {
	return t.ExpiresAt != nil && t.ExpiresAt.IsZero()
}

// IsExpired reports whether a TTL token has passed its expiry time.
// Persistent and ephemeral tokens never expire by this definition.
func (t *Token) IsExpired() bool {
	return t.ExpiresAt != nil && !t.ExpiresAt.IsZero() && time.Now().UTC().After(*t.ExpiresAt)
}

// State is the decrypted vault contents, held in memory only while unsealed.
// It is serialised to JSON before encryption and deserialised after decryption.
type State struct {
	// Keys holds all stored secrets as "namespace/name" → plaintext value pairs.
	Keys map[string]string `json:"keys"`

	// Tokens holds all persistent access credentials. The ephemeral root token
	// is never stored here.
	Tokens []Token `json:"tokens"`
}

// Zero explicitly clears all sensitive data from memory. Call this whenever
// the unsealed state is no longer needed (e.g. on shutdown or re-seal).
func (s *State) Zero() {
	for k, v := range s.Keys {
		b := []byte(v)
		for i := range b {
			b[i] = 0
		}
		delete(s.Keys, k)
	}
	s.Keys = nil
	s.Tokens = nil
}

// normalize applies backward-compatible defaults to state loaded from disk.
// Tokens without a Role are treated as admin tokens (preserving old behaviour).
// Tokens without a Hash cannot be authenticated after the hashing migration
// and are dropped; the operator must create replacement tokens.
func (s *State) normalize() {
	kept := s.Tokens[:0]
	for i := range s.Tokens {
		t := &s.Tokens[i]
		if t.Role == "" {
			t.Role = RoleAdmin
		}
		if t.Hash == "" {
			slog.Warn("dropping pre-migration token without hash; create a replacement token", "name", t.Name)
			continue
		}
		kept = append(kept, *t)
	}
	s.Tokens = kept
}

// Vault manages the encrypted vault file on disk.
type Vault struct {
	path   string
	params KDFParams
}

// New creates a Vault backed by the file at path, using params for key
// derivation. No I/O is performed until Unseal, Seal, or Init is called.
func New(path string, params KDFParams) *Vault {
	return &Vault{path: path, params: params}
}

// Unseal decrypts the vault file using passphrase and returns the in-memory
// State. The caller must call State.Zero() when finished to clear key material.
func (v *Vault) Unseal(passphrase []byte) (*State, error) {
	data, err := os.ReadFile(v.path)
	if err != nil {
		return nil, fmt.Errorf("reading vault: %w", err)
	}

	if len(data) < MinVaultSize {
		return nil, fmt.Errorf("vault file too short (%d bytes, minimum %d): corrupt or empty",
			len(data), MinVaultSize)
	}

	// Parse header using named offsets derived from size constants.
	magicEnd := MagicSize
	versionEnd := magicEnd + VersionSize
	saltEnd := versionEnd + SaltSize
	nonceEnd := saltEnd + NonceSize

	if string(data[:magicEnd]) != magic {
		return nil, errors.New("invalid vault magic — not a cordova vault file")
	}
	if data[magicEnd] != currentVersion {
		return nil, fmt.Errorf("unsupported vault version 0x%02x — expected 0x%02x",
			data[magicEnd], currentVersion)
	}

	salt := data[versionEnd:saltEnd]
	nonce := data[saltEnd:nonceEnd]
	ciphertext := data[nonceEnd:]

	// Derive the AES key from the passphrase using Argon2id.
	key := argon2.IDKey(passphrase, salt, v.params.Time, v.params.Memory, v.params.Threads, AESKeySize)
	defer zeroBytes(key)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("creating AES cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("creating GCM: %w", err)
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		// Do not expose whether the failure is a bad passphrase or corrupt file.
		return nil, errors.New("decryption failed — wrong passphrase or corrupt vault")
	}
	defer zeroBytes(plaintext)

	var state State
	if err := json.Unmarshal(plaintext, &state); err != nil {
		return nil, fmt.Errorf("parsing vault contents: %w", err)
	}

	if state.Keys == nil {
		state.Keys = make(map[string]string)
	}
	if state.Tokens == nil {
		state.Tokens = []Token{}
	}

	// Apply backward-compatible defaults before returning.
	state.normalize()

	return &state, nil
}

// Seal encrypts state and writes it atomically to the vault file using a fresh
// salt and nonce. The previous vault file is replaced only after the new one
// is successfully written.
func (v *Vault) Seal(state *State, passphrase []byte) error {
	plaintext, err := json.Marshal(state)
	if err != nil {
		return fmt.Errorf("serialising vault: %w", err)
	}
	defer zeroBytes(plaintext)

	// Generate fresh salt and nonce on every seal for forward secrecy.
	salt := make([]byte, SaltSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return fmt.Errorf("generating salt: %w", err)
	}

	nonce := make([]byte, NonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return fmt.Errorf("generating nonce: %w", err)
	}

	key := argon2.IDKey(passphrase, salt, v.params.Time, v.params.Memory, v.params.Threads, AESKeySize)
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

	// Assemble file: magic + version + salt + nonce + ciphertext.
	out := make([]byte, 0, HeaderSize+len(ciphertext))
	out = append(out, []byte(magic)...)
	out = append(out, currentVersion)
	out = append(out, salt...)
	out = append(out, nonce...)
	out = append(out, ciphertext...)

	// Atomic write: write to a temp file then rename into place so a crash
	// mid-write cannot leave the vault in a corrupt state.
	tmp := v.path + ".tmp"
	if err := os.WriteFile(tmp, out, 0600); err != nil {
		return fmt.Errorf("writing vault tmp file: %w", err)
	}
	if err := os.Rename(tmp, v.path); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("renaming vault into place: %w", err)
	}

	return nil
}

// Init creates a new, empty vault at path encrypted with passphrase.
// Returns an error if a vault file already exists at that path.
func (v *Vault) Init(passphrase []byte) error {
	if _, err := os.Stat(v.path); err == nil {
		return fmt.Errorf("vault already exists at %s — use 'cordova-vault vault init' to re-encrypt", v.path)
	}
	state := &State{
		Keys:   make(map[string]string),
		Tokens: []Token{},
	}
	return v.Seal(state, passphrase)
}

// Exists reports whether the vault file is present on disk.
func (v *Vault) Exists() bool {
	_, err := os.Stat(v.path)
	return err == nil
}

// Path returns the absolute path to the vault file.
func (v *Vault) Path() string {
	return v.path
}

// zeroBytes overwrites every byte of b with zero to remove sensitive material
// from memory. Used for keys, passphrases, and plaintext buffers.
func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
