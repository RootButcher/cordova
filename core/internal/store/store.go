// cordova/core/internal/store/store.go

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

type Store struct {
	mu    sync.RWMutex
	state *vault.State
}

func New() *Store {
	return &Store{}
}

func (s *Store) Load(state *vault.State) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state = state
}

func (s *Store) IsSealed() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.state == nil
}

func (s *Store) Zero() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state != nil {
		s.state.Zero()
		s.state = nil
	}
}

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

func validateKeyName(name string) error {
	return validate.ValidateKeyName(name)
}

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

func (s *Store) AddToken(
	name string,
	description string,
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

func (s *Store) RevokeAll() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state == nil {
		return fmt.Errorf("store is sealed")
	}
	s.state.Tokens = []vault.Token{}
	return nil
}

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
