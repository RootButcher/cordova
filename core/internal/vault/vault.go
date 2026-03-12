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

type KDFParams struct {
	Time    uint32
	Memory  uint32
	Threads uint8
}
type TokenRole string

// EphemeralExpiry returns the sentinel *time.Time used to mark a token as
// ephemeral (process-scoped)
//
// The zero time (0001-01-01 00:00:00 UTC) is used as the sentinel because:
//   - nil already means "persistent / no expiry"
//   - A real TTL is always a future timestamp, never year 1
//   - The zero value is unambiguous and easy to detect with time.Time.IsZero()
func EphemeralExpiry() *time.Time {
	t := time.Time{}
	return &t
}

type Token struct {
	Name        string     `json:"name"`
	Hash        string     `json:"hash"`
	Description string     `json:"description"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
	CIDRs       []string   `json:"cidrs,omitempty"`
	Namespaces  []string   `json:"namespaces,omitempty"`
	Keys        []string   `json:"keys,omitempty"`
	Writable    bool       `json:"writable,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	LastUsed    *time.Time `json:"last_used,omitempty"`
}

func (t *Token) IsPersistent() bool {
	return t.ExpiresAt == nil
}
func (t *Token) IsEphemeral() bool {
	return t.ExpiresAt != nil && t.ExpiresAt.IsZero()
}
func (t *Token) IsExpired() bool {
	return t.ExpiresAt != nil && !t.ExpiresAt.IsZero() && time.Now().UTC().After(*t.ExpiresAt)
}

type State struct {
	Keys   map[string]string `json:"keys"`
	Tokens []Token           `json:"tokens"`
}

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

type Vault struct {
	path   string
	params KDFParams
}

func New(path string, params KDFParams) *Vault {
	return &Vault{path: path, params: params}
}

func (v *Vault) Unseal(passphrase []byte) (*State, error) {
	data, err := os.ReadFile(v.path)
	if err != nil {
		return nil, fmt.Errorf("reading vault: %w", err)
	}

	if len(data) < MinVaultSize {
		return nil, fmt.Errorf("vault file too short (%d bytes, minimum %d): corrupt or empty",
			len(data), MinVaultSize)
	}

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

	return &state, nil
}
func (v *Vault) Seal(state *State, passphrase []byte) error {
	plaintext, err := json.Marshal(state)
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

	out := make([]byte, 0, HeaderSize+len(ciphertext))
	out = append(out, []byte(magic)...)
	out = append(out, currentVersion)
	out = append(out, salt...)
	out = append(out, nonce...)
	out = append(out, ciphertext...)

	tmp := v.path + ".tmp"
	if err := os.WriteFile(tmp, out, 0600); err != nil {
		return fmt.Errorf("writing vault tmp file: %w", err)
	}
	if err := os.Rename(tmp, v.path); err != nil {
		_ = os.Remove(tmp) //TODO report error here to log as error
		return fmt.Errorf("renaming vault into place: %w", err)
	}
	return nil
}

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

func (v *Vault) Exists() bool {
	_, err := os.Stat(v.path)
	return err == nil
}

func (v *Vault) Path() string {
	return v.path
}

func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
