// cordova/core/internal/store/store_test.go
//
// Tests for the in-memory store: key CRUD, token CRUD, snapshot correctness,
// and the expiry / ephemeral sentinel logic.
//
// WHY TEST THE STORE SEPARATELY FROM THE VAULT?
// -----------------------------------------------
// The store and the vault package have different responsibilities:
//   vault  — encrypts/decrypts a file
//   store  — holds decrypted state in memory and provides thread-safe access
//
// Testing them separately lets you locate failures instantly. If a round-trip
// test fails you immediately know whether the problem is in crypto or in the
// in-memory logic.
//
// WHAT "t.Helper()" DOES
// ----------------------
// When a helper function calls t.Fatalf, Go normally reports the failure at
// the line inside the helper. t.Helper() makes Go report the line in the
// CALLER instead, which is far more useful when debugging.

package store

import (
	"testing"
	"time"

	"cordova/core/internal/vault"
)

// ── Setup helpers ─────────────────────────────────────────────────────────────

// newLoadedStore creates a Store pre-loaded with an empty vault.State.
// Most tests start from this so they don't have to repeat the Load call.
func newLoadedStore(t *testing.T) *Store {
	t.Helper()
	s := New()
	s.Load(&vault.State{
		Keys:   make(map[string]string),
		Tokens: []vault.Token{},
	})
	return s
}

// ── Sealed store ──────────────────────────────────────────────────────────────

// TestSealedStoreRejectsOperations verifies that every operation returns an
// error when the store has not been loaded (i.e. the vault is still sealed).
func TestSealedStoreRejectsOperations(t *testing.T) {
	s := New() // no Load call — store remains sealed

	if !s.IsSealed() {
		t.Error("expected IsSealed() == true before Load")
	}

	// Every CRUD method should return a non-nil error when sealed.
	if _, err := s.GetKey("any"); err == nil {
		t.Error("GetKey: expected error on sealed store")
	}
	if err := s.SetKey("ns/k", "v"); err == nil {
		t.Error("SetKey: expected error on sealed store")
	}
	if _, err := s.ListKeys(); err == nil {
		t.Error("ListKeys: expected error on sealed store")
	}
	if _, err := s.ListTokens(); err == nil {
		t.Error("ListTokens: expected error on sealed store")
	}
}

// ── Key name validation ───────────────────────────────────────────────────────

// TestValidateKeyName checks valid and invalid key names exhaustively.
//
// TABLE-DRIVEN TESTS
// Instead of writing one function per case, Go idiom is to define a slice of
// structs — one struct per case — and loop over them. Each iteration calls
// t.Run with a sub-test name so you can run a single case with:
//
//	go test -run TestValidateKeyName/no_slash
//
// This approach scales: adding a new case is one line in the table.
func TestValidateKeyName(t *testing.T) {
	tests := []struct {
		name    string // sub-test label
		input   string // key name to validate
		wantErr bool   // true if we expect an error
	}{
		// Valid
		{"simple", "prod/db-pass", false},
		{"numbers", "prod/key1", false},
		{"hyphens", "my-ns/my-key", false},
		{"underscores", "my_ns/my_key", false},

		// Invalid — structure
		{"empty", "", true},
		{"no slash", "secret", true},
		{"blank namespace", "/key", true},
		{"blank name", "ns/", true},
		{"two slashes", "a/b/c", true},
		{"only slash", "/", true},

		// Invalid — whitespace
		{"space in name", "ns/my key", true},
		{"space in namespace", "my ns/key", true},
		{"leading space", " ns/key", true},
		{"trailing space", "ns/key ", true},
		{"tab in name", "ns/key\t", true},
		{"newline in namespace", "ns\n/key", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateKeyName(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateKeyName(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			}
		})
	}
}

// ── Key operations ────────────────────────────────────────────────────────────

// TestKeySetAndGet verifies basic add and retrieval.
func TestKeySetAndGet(t *testing.T) {
	s := newLoadedStore(t)

	if err := s.SetKey("prod/db-pass", "s3cr3t"); err != nil {
		t.Fatalf("SetKey: %v", err)
	}

	val, err := s.GetKey("prod/db-pass")
	if err != nil {
		t.Fatalf("GetKey: %v", err)
	}
	if val != "s3cr3t" {
		t.Errorf("got %q, want %q", val, "s3cr3t")
	}
}

// TestKeyOverwrite verifies that SetKey on an existing name replaces the value.
func TestKeyOverwrite(t *testing.T) {
	s := newLoadedStore(t)

	_ = s.SetKey("test/key", "original")
	_ = s.SetKey("test/key", "updated")

	val, _ := s.GetKey("test/key")
	if val != "updated" {
		t.Errorf("got %q, want %q", val, "updated")
	}
}

// TestKeyGetMissing verifies that fetching a non-existent key returns an error.
func TestKeyGetMissing(t *testing.T) {
	s := newLoadedStore(t)
	_, err := s.GetKey("does/not/exist")
	if err == nil {
		t.Error("expected error for missing key, got nil")
	}
}

// TestKeyDelete verifies deletion and double-delete error behaviour.
func TestKeyDelete(t *testing.T) {
	s := newLoadedStore(t)
	_ = s.SetKey("test/key", "v")

	// First delete succeeds.
	if err := s.DeleteKey("test/key"); err != nil {
		t.Fatalf("DeleteKey: %v", err)
	}

	// Key should no longer exist.
	if _, err := s.GetKey("test/key"); err == nil {
		t.Error("expected error after delete, got nil")
	}

	// Second delete on the same key should fail.
	if err := s.DeleteKey("test/key"); err == nil {
		t.Error("expected error for double-delete, got nil")
	}
}

// TestListKeys verifies that ListKeys returns all names and nothing else.
func TestListKeys(t *testing.T) {
	s := newLoadedStore(t)
	_ = s.SetKey("a/one", "1")
	_ = s.SetKey("b/two", "2")
	_ = s.SetKey("c/three", "3")

	keys, err := s.ListKeys()
	if err != nil {
		t.Fatalf("ListKeys: %v", err)
	}
	if len(keys) != 3 {
		t.Errorf("expected 3 keys, got %d: %v", len(keys), keys)
	}
}

// ── Token operations ──────────────────────────────────────────────────────────

// TestAddAndFindToken verifies that a created token can be found using the
// one-time secret returned by AddToken.
func TestAddAndFindToken(t *testing.T) {
	s := newLoadedStore(t)

	secret, err := s.AddToken("ci-runner", "CI runner token", vault.RoleAdmin, nil, nil, nil, nil, false)
	if err != nil {
		t.Fatalf("AddToken: %v", err)
	}
	if secret == "" {
		t.Fatal("AddToken returned empty secret")
	}

	tok, err := s.FindToken(secret)
	if err != nil {
		t.Fatalf("FindToken: %v", err)
	}
	if tok.Name != "ci-runner" {
		t.Errorf("name: got %q, want %q", tok.Name, "ci-runner")
	}
	if tok.Description != "CI runner token" {
		t.Errorf("description: got %q, want %q", tok.Description, "CI runner token")
	}
	if tok.Role != vault.RoleAdmin {
		t.Errorf("role: got %q, want %q", tok.Role, vault.RoleAdmin)
	}
}

// TestAddTokenDuplicateName verifies that two tokens with the same name cannot
// be created.
func TestAddTokenDuplicateName(t *testing.T) {
	s := newLoadedStore(t)

	if _, err := s.AddToken("ops-box", "first", vault.RoleAdmin, nil, nil, nil, nil, false); err != nil {
		t.Fatalf("first AddToken: %v", err)
	}
	if _, err := s.AddToken("ops-box", "second", vault.RoleAdmin, nil, nil, nil, nil, false); err == nil {
		t.Error("expected error for duplicate name, got nil")
	}
}

// TestRevokeToken verifies that a token cannot be found after revocation.
func TestRevokeToken(t *testing.T) {
	s := newLoadedStore(t)
	secret, _ := s.AddToken("revoke-target", "to be deleted", vault.RoleAdmin, nil, nil, nil, nil, false)

	if err := s.RevokeToken("revoke-target"); err != nil {
		t.Fatalf("RevokeToken: %v", err)
	}

	// The secret should no longer match any stored hash.
	if _, err := s.FindToken(secret); err == nil {
		t.Error("expected error after revoke, got nil")
	}

	// Revoking a non-existent name should return an error.
	if err := s.RevokeToken("does-not-exist"); err == nil {
		t.Error("expected error for non-existent name, got nil")
	}
}

// TestRevokeAll verifies that RevokeAll removes every token.
func TestRevokeAll(t *testing.T) {
	s := newLoadedStore(t)
	s.AddToken("tok-a", "a", vault.RoleAdmin, nil, nil, nil, nil, false) //nolint:errcheck
	s.AddToken("tok-b", "b", vault.RoleAdmin, nil, nil, nil, nil, false) //nolint:errcheck
	s.AddToken("tok-c", "c", vault.RoleAdmin, nil, nil, nil, nil, false) //nolint:errcheck

	if err := s.RevokeAll(); err != nil {
		t.Fatalf("RevokeAll: %v", err)
	}

	tokens, _ := s.ListTokens()
	if len(tokens) != 0 {
		t.Errorf("expected 0 tokens after RevokeAll, got %d", len(tokens))
	}
}

// TestTouchToken verifies that TouchToken updates LastUsed without panicking on
// a missing name (it is intentionally a no-op for unknown names).
func TestTouchToken(t *testing.T) {
	s := newLoadedStore(t)
	secret, _ := s.AddToken("touch-tok", "test token", vault.RoleAdmin, nil, nil, nil, nil, false)

	// Before touch: LastUsed should be nil.
	tok, _ := s.FindToken(secret)
	if tok.LastUsed != nil {
		t.Error("expected nil LastUsed before touch")
	}

	s.TouchToken("touch-tok")

	tok, _ = s.FindToken(secret)
	if tok.LastUsed == nil {
		t.Error("expected non-nil LastUsed after touch")
	}

	// Touching a non-existent name must not panic.
	s.TouchToken("does-not-exist")
}

// ── Snapshot ──────────────────────────────────────────────────────────────────

// TestSnapshotExcludesEphemeralTokens verifies the critical invariant: ephemeral
// tokens must never appear in the snapshot written to disk.
//
// WHAT IS AN EPHEMERAL TOKEN?
// A token whose ExpiresAt is set to the zero time (0001-01-01). This sentinel
// value means "process-scoped only — never persist to disk". The root token
// created by --gen-root is ephemeral.
func TestSnapshotExcludesEphemeralTokens(t *testing.T) {
	s := newLoadedStore(t)

	// Add a persistent token (nil ExpiresAt).
	if _, err := s.AddToken("persistent", "persistent token", vault.RoleAdmin, nil, nil, nil, nil, false); err != nil {
		t.Fatalf("AddToken persistent: %v", err)
	}

	// Add an ephemeral token (zero-time sentinel).
	ephemeralExpiry := vault.EphemeralExpiry()
	if _, err := s.AddToken("ephemeral", "ephemeral token", vault.RoleAdmin, ephemeralExpiry, nil, nil, nil, false); err != nil {
		t.Fatalf("AddToken ephemeral: %v", err)
	}

	snap, err := s.Snapshot()
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}

	if len(snap.Tokens) != 1 {
		t.Fatalf("snapshot should contain 1 token, got %d", len(snap.Tokens))
	}
	if snap.Tokens[0].Name != "persistent" {
		t.Errorf("snapshot contains wrong token %q — should only include persistent tokens", snap.Tokens[0].Name)
	}
}

// TestSnapshotIsADeepCopy verifies that mutating the snapshot does not affect
// the live store state, and vice versa.
//
// DEEP COPY vs SHALLOW COPY
// A shallow copy just copies pointer values — both the original and the copy
// point to the same underlying data. A deep copy duplicates all the data so
// the two are fully independent. The store must return deep copies so that
// the vault.Seal call doesn't race with ongoing store mutations.
func TestSnapshotIsADeepCopy(t *testing.T) {
	s := newLoadedStore(t)
	_ = s.SetKey("ns/original", "value")

	snap, _ := s.Snapshot()

	// Mutate the snapshot.
	snap.Keys["injected"] = "extra"

	// The live store must be unaffected.
	keys, _ := s.ListKeys()
	for _, k := range keys {
		if k == "injected" {
			t.Error("mutating snapshot affected the live store — Snapshot is not a deep copy")
		}
	}
}

// ── Expiry ────────────────────────────────────────────────────────────────────

// TestExpiredTokenIsFound verifies that FindTokenByID still returns an expired
// token — the store itself does not delete it on read.
//
// SEPARATION OF CONCERNS
// The store is a dumb data container. It has no opinion about what to do with
// an expired token — that's policy. The auth layer (currently socket.authenticate,
// eventually its own middleware) is responsible for detecting IsExpired() and
// deciding to delete the token. Keeping the store ignorant of this policy makes
// both layers easier to test and change independently.
func TestExpiredTokenIsFound(t *testing.T) {
	s := newLoadedStore(t)

	past := time.Now().UTC().Add(-1 * time.Hour)
	secret, _ := s.AddToken("expired-tok", "expired token", vault.RoleAdmin, &past, nil, nil, nil, false)

	tok, err := s.FindToken(secret)
	if err != nil {
		t.Fatalf("FindToken: %v", err)
	}
	if !tok.IsExpired() {
		t.Error("expected token to report as expired")
	}
}

// TestExpiredTokenRevokedOnUse simulates what the auth layer does: detect
// expiry via IsExpired(), then call RevokeToken to clean it up.
// After that, FindTokenByID must return an error (not the expired token).
//
// This test belongs here — in the store — not in the socket tests, because
// this is purely data lifecycle logic. The socket is just the transport that
// triggers it.
func TestExpiredTokenRevokedOnUse(t *testing.T) {
	s := newLoadedStore(t)

	past := time.Now().UTC().Add(-1 * time.Hour)
	secret, _ := s.AddToken("expired-cleanup", "expired token", vault.RoleAdmin, &past, nil, nil, nil, false)

	// Simulate what the auth layer does when it finds an expired token.
	tok, _ := s.FindToken(secret)
	if tok.IsExpired() {
		if err := s.RevokeToken(tok.Name); err != nil {
			t.Fatalf("RevokeToken on expired: %v", err)
		}
	}

	// The token must now be gone.
	if _, err := s.FindToken(secret); err == nil {
		t.Error("expected error after revoking expired token, got nil")
	}
}

// TestZeroClearsState verifies that Zero makes the store sealed and clears
// the internal state pointer.
func TestZeroClearsState(t *testing.T) {
	s := newLoadedStore(t)
	_ = s.SetKey("ns/sensitive", "value")

	s.Zero()

	if !s.IsSealed() {
		t.Error("expected IsSealed() == true after Zero")
	}
	if _, err := s.GetKey("sensitive"); err == nil {
		t.Error("expected error after Zero, got nil")
	}
}
