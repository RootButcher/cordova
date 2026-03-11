// cordova/core/internal/store/store.go
//
// Package store holds the unsealed vault state in memory and provides
// thread-safe CRUD operations for keys and tokens. All mutations update only
// the in-memory state; callers must call Snapshot + vault.Seal to persist
// changes to disk.

package store

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"cordova/core/internal/vault"
	"cordova/core/validate"
)

// Store holds the unsealed vault state in memory and provides thread-safe
// CRUD for keys and tokens via a read-write mutex. The zero value is a sealed
// (empty) store; call Load to populate it after unsealing the vault.
type Store struct {
	mu    sync.RWMutex
	state *vault.State
}

// New returns an empty, sealed Store. Call Load to populate it.
func New() *Store {
	return &Store{}
}

// Load populates the store from a decrypted vault State. The store takes
// ownership of state; the caller should not use state directly after this.
func (s *Store) Load(state *vault.State) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state = state
}

// IsSealed reports whether the store has been loaded with vault state.
// Returns true when the vault is sealed (state is nil).
func (s *Store) IsSealed() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.state == nil
}

// Zero clears all key material from memory and marks the store as sealed.
// After this call IsSealed returns true and all operations return errors.
func (s *Store) Zero() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state != nil {
		s.state.Zero()
		s.state = nil
	}
}

// Snapshot returns a deep copy of the current State suitable for passing to
// vault.Seal. Ephemeral tokens are excluded — they must never be written to
// disk. Expired TTL tokens remain on disk until auth evicts them. The copy is
// independent of the live state; mutations to either do not affect the other.
func (s *Store) Snapshot() (*vault.State, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.state == nil {
		return nil, fmt.Errorf("store is sealed")
	}
	snap := &vault.State{
		Keys:   make(map[string]string, len(s.state.Keys)),
		Tokens: []vault.Token{},
	}
	for k, v := range s.state.Keys {
		snap.Keys[k] = v
	}
	for _, t := range s.state.Tokens {
		if !t.IsEphemeral() {
			snap.Tokens = append(snap.Tokens, t)
		}
	}
	return snap, nil
}

// ── Keys ─────────────────────────────────────────────────────────────────────

// GetKey returns the plaintext value for the key identified by name
// ("namespace/name"). Returns an error if the store is sealed or the key
// does not exist.
func (s *Store) GetKey(name string) (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.state == nil {
		return "", fmt.Errorf("store is sealed")
	}
	v, ok := s.state.Keys[name]
	if !ok {
		return "", fmt.Errorf("key not found: %s", name)
	}
	return v, nil
}

// ListKeys returns all key names currently stored. The returned slice is a
// snapshot; later mutations do not affect it.
func (s *Store) ListKeys() ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.state == nil {
		return nil, fmt.Errorf("store is sealed")
	}
	names := make([]string, 0, len(s.state.Keys))
	for k := range s.state.Keys {
		names = append(names, k)
	}
	return names, nil
}

// validateKeyName delegates to the shared validate package. Kept as a private
// wrapper so internal callers don't need to import validate directly.
func validateKeyName(name string) error {
	return validate.ValidateKeyName(name)
}

// SetKey adds or overwrites a key in the in-memory store. Call Snapshot +
// vault.Seal afterwards to persist the change to disk.
func (s *Store) SetKey(name, value string) error {
	if err := validateKeyName(name); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state == nil {
		return fmt.Errorf("store is sealed")
	}
	s.state.Keys[name] = value
	return nil
}

// DeleteKey removes a key from the in-memory store. Returns an error if the
// store is sealed or the key does not exist. Call Snapshot + vault.Seal to
// persist.
func (s *Store) DeleteKey(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state == nil {
		return fmt.Errorf("store is sealed")
	}
	if _, ok := s.state.Keys[name]; !ok {
		return fmt.Errorf("key not found: %s", name)
	}
	delete(s.state.Keys, name)
	return nil
}

// ── Tokens ────────────────────────────────────────────────────────────────────

// FindToken looks up a token by the raw bearer secret. The secret is hashed
// with SHA-256 and compared against stored hashes using constant-time
// comparison to prevent timing attacks. Returns an error if the store is
// sealed or no matching token exists.
func (s *Store) FindToken(secret string) (*vault.Token, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.state == nil {
		return nil, fmt.Errorf("store is sealed")
	}
	raw, err := hex.DecodeString(secret)
	if err != nil {
		return nil, fmt.Errorf("token not found")
	}
	sum := sha256.Sum256(raw)
	candidate := hex.EncodeToString(sum[:])
	for i := range s.state.Tokens {
		if subtle.ConstantTimeCompare([]byte(s.state.Tokens[i].Hash), []byte(candidate)) == 1 {
			t := s.state.Tokens[i]
			return &t, nil
		}
	}
	return nil, fmt.Errorf("token not found")
}

// ListTokens returns a copy of all stored tokens. The returned slice is a
// snapshot; later mutations do not affect it.
func (s *Store) ListTokens() ([]vault.Token, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.state == nil {
		return nil, fmt.Errorf("store is sealed")
	}
	out := make([]vault.Token, len(s.state.Tokens))
	copy(out, s.state.Tokens)
	return out, nil
}

// AddToken creates a new token with a cryptographically random secret, stores
// a SHA-256 hash of that secret, and returns the raw secret to the caller.
// The secret is shown once and never stored — only the hash is kept on disk.
//
// name must be a unique slug (see validate.ValidateTokenName). expiresAt
// controls persistence: nil = persistent, vault.EphemeralExpiry() =
// process-scoped (never written to disk), future *time.Time = TTL.
func (s *Store) AddToken(
	name string,
	description string,
	role vault.TokenRole,
	expiresAt *time.Time,
	cidrs, namespaces, keys []string,
	writable bool,
) (secret string, err error) {
	if err := validate.ValidateTokenName(name); err != nil {
		return "", err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state == nil {
		return "", fmt.Errorf("store is sealed")
	}

	for _, t := range s.state.Tokens {
		if t.Name == name {
			return "", fmt.Errorf("token name already in use: %q", name)
		}
	}

	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generating token secret: %w", err)
	}
	secretVal := hex.EncodeToString(raw)
	sum := sha256.Sum256(raw)
	hash := hex.EncodeToString(sum[:])

	t := vault.Token{
		Name:        name,
		Hash:        hash,
		Description: description,
		Role:        role,
		ExpiresAt:   expiresAt,
		CIDRs:       cidrs,
		Namespaces:  namespaces,
		Keys:        keys,
		Writable:    writable,
		CreatedAt:   time.Now().UTC(),
	}
	s.state.Tokens = append(s.state.Tokens, t)
	return secretVal, nil
}

// RevokeToken removes the token with the given name from the in-memory store.
// Returns an error if the store is sealed or no token with that name exists.
func (s *Store) RevokeToken(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state == nil {
		return fmt.Errorf("store is sealed")
	}
	for i, t := range s.state.Tokens {
		if t.Name == name {
			s.state.Tokens = append(s.state.Tokens[:i], s.state.Tokens[i+1:]...)
			return nil
		}
	}
	return fmt.Errorf("token not found: %s", name)
}

// RevokeAll removes every token from the in-memory store.
func (s *Store) RevokeAll() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state == nil {
		return fmt.Errorf("store is sealed")
	}
	s.state.Tokens = []vault.Token{}
	return nil
}

// TouchToken updates the LastUsed timestamp for the token with the given name
// to the current UTC time. Silently does nothing if the store is sealed or the
// token does not exist.
func (s *Store) TouchToken(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state == nil {
		return
	}
	now := time.Now().UTC()
	for i := range s.state.Tokens {
		if s.state.Tokens[i].Name == name {
			s.state.Tokens[i].LastUsed = &now
			return
		}
	}
}
