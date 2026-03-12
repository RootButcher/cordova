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

// ── SecretsStore ──────────────────────────────────────────────────────────────

// SecretsStore is an in-memory cache of the secrets vault state.
type SecretsStore struct {
	mu    sync.RWMutex
	state *vault.SecretsState
}

// NewSecretsStore creates an empty, sealed SecretsStore.
func NewSecretsStore() *SecretsStore {
	return &SecretsStore{}
}

// Load replaces the in-memory state with the given snapshot.
func (s *SecretsStore) Load(state *vault.SecretsState) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state = state
}

// IsSealed reports whether the store has no loaded state.
func (s *SecretsStore) IsSealed() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.state == nil
}

// Zero overwrites all secret values and clears the state.
func (s *SecretsStore) Zero() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state != nil {
		s.state.Zero()
		s.state = nil
	}
}

// Snapshot returns a deep copy of the current state for persistence.
func (s *SecretsStore) Snapshot() (*vault.SecretsState, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.state == nil {
		return nil, fmt.Errorf("store is sealed")
	}
	snap := &vault.SecretsState{
		Keys: make(map[string]string, len(s.state.Keys)),
	}
	for k, v := range s.state.Keys {
		snap.Keys[k] = v
	}
	return snap, nil
}

// GetKey returns the value for the named key.
func (s *SecretsStore) GetKey(name string) (string, error) {
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

// ListKeys returns the names of all stored keys.
func (s *SecretsStore) ListKeys() ([]string, error) {
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

// SetKey creates or replaces a key value.
func (s *SecretsStore) SetKey(name, value string) error {
	if err := validate.KeyName(name); err != nil {
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

// DeleteKey removes a key from the store.
func (s *SecretsStore) DeleteKey(name string) error {
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

// ── UserStore ─────────────────────────────────────────────────────────────────

// UserStore is an in-memory cache of the users vault state.
type UserStore struct {
	mu    sync.RWMutex
	state *vault.UsersState
}

// NewUserStore creates an empty, sealed UserStore.
func NewUserStore() *UserStore {
	return &UserStore{}
}

// Load replaces the in-memory state with the given snapshot.
func (s *UserStore) Load(state *vault.UsersState) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state = state
}

// IsSealed reports whether the store has no loaded state.
func (s *UserStore) IsSealed() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.state == nil
}

// Zero clears the state.
func (s *UserStore) Zero() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state = nil
}

// Snapshot returns a copy of the UsersState with ephemeral tokens excluded.
func (s *UserStore) Snapshot() (*vault.UsersState, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.state == nil {
		return nil, fmt.Errorf("store is sealed")
	}
	snap := &vault.UsersState{
		Users: make([]vault.User, 0, len(s.state.Users)),
	}
	for _, u := range s.state.Users {
		uc := u
		uc.Tokens = nil
		for _, t := range u.Tokens {
			if !t.IsEphemeral() {
				uc.Tokens = append(uc.Tokens, t)
			}
		}
		snap.Users = append(snap.Users, uc)
	}
	return snap, nil
}

// GetUser returns a copy of the named user.
func (s *UserStore) GetUser(name string) (*vault.User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.state == nil {
		return nil, fmt.Errorf("store is sealed")
	}
	for i := range s.state.Users {
		if s.state.Users[i].Name == name {
			u := s.state.Users[i]
			return &u, nil
		}
	}
	return nil, fmt.Errorf("user not found: %s", name)
}

// ListUsers returns a copy of all users.
func (s *UserStore) ListUsers() ([]vault.User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.state == nil {
		return nil, fmt.Errorf("store is sealed")
	}
	out := make([]vault.User, len(s.state.Users))
	copy(out, s.state.Users)
	return out, nil
}

// Children returns all direct children of the named user.
func (s *UserStore) Children(parentName string) ([]vault.User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.state == nil {
		return nil, fmt.Errorf("store is sealed")
	}
	var out []vault.User
	for _, u := range s.state.Users {
		if u.Parent == parentName {
			out = append(out, u)
		}
	}
	return out, nil
}

// AddUser creates a new user as a child of parent. The caller must hold writeMu.
// Child permissions must be a subset of the parent's permissions.
func (s *UserStore) AddUser(
	name, parent string,
	admin bool,
	namespaces, keys, sockets []string,
	writable bool,
) error {
	if err := validate.Username(name); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state == nil {
		return fmt.Errorf("store is sealed")
	}

	for _, u := range s.state.Users {
		if u.Name == name {
			return fmt.Errorf("user already exists: %q", name)
		}
	}

	parentIdx := -1
	for i, u := range s.state.Users {
		if u.Name == parent {
			parentIdx = i
			break
		}
	}
	if parentIdx < 0 {
		return fmt.Errorf("parent user not found: %q", parent)
	}
	p := s.state.Users[parentIdx]

	if !p.Admin {
		return fmt.Errorf("parent user %q is not an admin", parent)
	}
	if admin && !p.Admin {
		return fmt.Errorf("child cannot have admin=true when parent does not")
	}
	// Root is implicitly writable; for non-root parents, check explicitly.
	if writable && !p.Writable && p.Name != "root" {
		return fmt.Errorf("child cannot be writable when parent is not")
	}
	if err := checkSubset("namespaces", namespaces, p.Namespaces); err != nil {
		return err
	}
	if err := checkSubset("keys", keys, p.Keys); err != nil {
		return err
	}
	if err := checkSubset("sockets", sockets, p.Sockets); err != nil {
		return err
	}

	s.state.Users = append(s.state.Users, vault.User{
		Name:       name,
		Parent:     parent,
		Admin:      admin,
		Namespaces: namespaces,
		Keys:       keys,
		Writable:   writable,
		Sockets:    sockets,
		CreatedAt:  time.Now().UTC(),
	})
	return nil
}

// DeleteUser removes a user and all their tokens. Returns an error if the user
// has children or is the root user. The caller must hold writeMu.
func (s *UserStore) DeleteUser(name string) error {
	if name == "root" {
		return fmt.Errorf("cannot delete root user")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state == nil {
		return fmt.Errorf("store is sealed")
	}

	for _, u := range s.state.Users {
		if u.Parent == name {
			return fmt.Errorf("user %q has children — delete them first", name)
		}
	}
	for i, u := range s.state.Users {
		if u.Name == name {
			s.state.Users = append(s.state.Users[:i], s.state.Users[i+1:]...)
			return nil
		}
	}
	return fmt.Errorf("user not found: %s", name)
}

// AddToken generates a new token for the named user and returns the one-time
// plaintext secret. The caller must hold writeMu.
func (s *UserStore) AddToken(
	username, name, description string,
	expiresAt *time.Time,
) (secret string, err error) {
	if err := validate.TokenName(name); err != nil {
		return "", err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state == nil {
		return "", fmt.Errorf("store is sealed")
	}

	userIdx := -1
	for i, u := range s.state.Users {
		if u.Name == username {
			userIdx = i
			break
		}
	}
	if userIdx < 0 {
		return "", fmt.Errorf("user not found: %q", username)
	}

	for _, t := range s.state.Users[userIdx].Tokens {
		if t.Name == name {
			return "", fmt.Errorf("token name already in use for user %q: %q", username, name)
		}
	}

	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generating token secret: %w", err)
	}
	secretVal := hex.EncodeToString(raw)
	sum := sha256.Sum256(raw)
	hash := hex.EncodeToString(sum[:])

	tok := vault.Token{
		Name:        name,
		Hash:        hash,
		Description: description,
		ExpiresAt:   expiresAt,
		CreatedAt:   time.Now().UTC(),
	}
	s.state.Users[userIdx].Tokens = append(s.state.Users[userIdx].Tokens, tok)
	return secretVal, nil
}

// FindToken looks up the user and token matching the given username and plaintext
// secret. It is safe to call concurrently.
func (s *UserStore) FindToken(username, secret string) (*vault.User, *vault.Token, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.state == nil {
		return nil, nil, fmt.Errorf("store is sealed")
	}

	raw, err := hex.DecodeString(secret)
	if err != nil {
		return nil, nil, fmt.Errorf("token not found")
	}
	sum := sha256.Sum256(raw)
	candidate := hex.EncodeToString(sum[:])

	for i := range s.state.Users {
		if s.state.Users[i].Name != username {
			continue
		}
		u := s.state.Users[i]
		for j := range u.Tokens {
			if subtle.ConstantTimeCompare([]byte(u.Tokens[j].Hash), []byte(candidate)) == 1 {
				t := u.Tokens[j]
				return &u, &t, nil
			}
		}
		return nil, nil, fmt.Errorf("token not found")
	}
	return nil, nil, fmt.Errorf("user not found: %q", username)
}

// RevokeToken removes the named token from the given user. The caller must
// hold writeMu.
func (s *UserStore) RevokeToken(username, tokenName string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state == nil {
		return fmt.Errorf("store is sealed")
	}
	for i := range s.state.Users {
		if s.state.Users[i].Name != username {
			continue
		}
		for j, t := range s.state.Users[i].Tokens {
			if t.Name == tokenName {
				s.state.Users[i].Tokens = append(
					s.state.Users[i].Tokens[:j],
					s.state.Users[i].Tokens[j+1:]...,
				)
				return nil
			}
		}
		return fmt.Errorf("token not found: %s", tokenName)
	}
	return fmt.Errorf("user not found: %q", username)
}

// RevokeAllTokens clears all tokens for the named user. If username is empty,
// all tokens for every user are revoked. The caller must hold writeMu.
func (s *UserStore) RevokeAllTokens(username string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state == nil {
		return fmt.Errorf("store is sealed")
	}
	found := false
	for i := range s.state.Users {
		if username == "" || s.state.Users[i].Name == username {
			s.state.Users[i].Tokens = []vault.Token{}
			found = true
		}
	}
	if username != "" && !found {
		return fmt.Errorf("user not found: %q", username)
	}
	return nil
}

// TouchToken updates the LastUsed timestamp for the named token. Call under
// writeMu to prevent the update racing with persist().
func (s *UserStore) TouchToken(username, tokenName string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state == nil {
		return
	}
	now := time.Now().UTC()
	for i := range s.state.Users {
		if s.state.Users[i].Name != username {
			continue
		}
		for j := range s.state.Users[i].Tokens {
			if s.state.Users[i].Tokens[j].Name == tokenName {
				s.state.Users[i].Tokens[j].LastUsed = &now
				return
			}
		}
	}
}

// UserTokenPair groups a token with its owning username.
type UserTokenPair struct {
	Username string
	Token    vault.Token
}

// ListAllTokens returns all tokens across all users with their owning username.
func (s *UserStore) ListAllTokens() ([]UserTokenPair, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.state == nil {
		return nil, fmt.Errorf("store is sealed")
	}
	var out []UserTokenPair
	for _, u := range s.state.Users {
		for _, t := range u.Tokens {
			out = append(out, UserTokenPair{Username: u.Name, Token: t})
		}
	}
	return out, nil
}

// ── helpers ───────────────────────────────────────────────────────────────────

// checkSubset returns an error if any element of child is absent from parent.
// A nil parent slice means unrestricted — any child values are permitted.
func checkSubset(field string, child, parent []string) error {
	if parent == nil {
		return nil
	}
	parentSet := make(map[string]struct{}, len(parent))
	for _, v := range parent {
		parentSet[v] = struct{}{}
	}
	for _, v := range child {
		if _, ok := parentSet[v]; !ok {
			return fmt.Errorf("%s: %q is not in parent's allowed set", field, v)
		}
	}
	return nil
}
