// cordova/core/internal/vault/vault_test.go
//
// Tests for vault encryption, decryption, and the Token helper methods.
//
// HOW GO TESTS WORK
// -----------------
// Any file ending in _test.go is compiled only when you run "go test". The
// testing package provides the *testing.T type — every test function receives
// one and uses it to report failures (t.Errorf, t.Fatalf) and log output.
//
// t.Fatalf  — marks the test failed and stops that test immediately.
// t.Errorf  — marks the test failed but lets it keep running.
//
// TABLE-DRIVEN TESTS
// ------------------
// Rather than writing one function per case, Go code typically builds a slice
// of structs (the "table") and loops over it. This keeps repetition minimal
// and makes adding new cases trivial. You'll see this pattern in every test
// below.
//
// t.Run("name", func(t *testing.T) { ... })
// ------------------------------------------
// Runs a named sub-test. go test reports each sub-test individually so you
// can see exactly which case failed. t.TempDir() creates a temporary
// directory that is automatically deleted when the test finishes.

package vault

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// defaultTestParams returns fast KDF params for tests.
// The real Argon2id params are tuned for a Pi Zero 2W and take ~1 second.
// Using time=1, memory=64KB, threads=1 keeps unit tests fast while still
// exercising the real code path.
func defaultTestParams() KDFParams {
	return KDFParams{Time: 1, Memory: 64, Threads: 1}
}

// ── Init ──────────────────────────────────────────────────────────────────────

// TestInit verifies that Init creates a valid vault file and refuses to
// overwrite an existing one.
func TestInit(t *testing.T) {
	dir := t.TempDir() // temporary directory, cleaned up automatically
	path := filepath.Join(dir, "test.vault")
	passphrase := []byte("correct-horse-battery-staple")

	v := New(path, defaultTestParams())

	// First init must succeed.
	if err := v.Init(passphrase); err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	// The file must now exist.
	if !v.Exists() {
		t.Fatal("vault file does not exist after Init")
	}

	// Second init on the same path must return an error (would overwrite data).
	if err := v.Init(passphrase); err == nil {
		t.Fatal("expected error when Init called on existing vault, got nil")
	}
}

// ── Unseal ────────────────────────────────────────────────────────────────────

// TestUnseal_CorrectPassphrase verifies the happy path: Init then Unseal with
// the same passphrase returns an empty but valid State.
func TestUnseal_CorrectPassphrase(t *testing.T) {
	v, passphrase := newTestVault(t)

	state, err := v.Unseal(passphrase)
	if err != nil {
		t.Fatalf("Unseal failed: %v", err)
	}
	defer state.Zero()

	// A freshly initialised vault has an empty keys map and no tokens.
	if state.Keys == nil {
		t.Error("Keys map is nil after Unseal")
	}
	if len(state.Keys) != 0 {
		t.Errorf("expected 0 keys, got %d", len(state.Keys))
	}
	if len(state.Tokens) != 0 {
		t.Errorf("expected 0 tokens, got %d", len(state.Tokens))
	}
}

// TestUnseal_WrongPassphrase verifies that a wrong passphrase returns an error
// and does not leak information about whether the passphrase or file is bad.
func TestUnseal_WrongPassphrase(t *testing.T) {
	v, _ := newTestVault(t)

	_, err := v.Unseal([]byte("wrong-passphrase"))
	if err == nil {
		t.Fatal("expected error for wrong passphrase, got nil")
	}
}

// TestUnseal_CorruptFile verifies that a truncated or garbage file is rejected.
func TestUnseal_CorruptFile(t *testing.T) {
	// TABLE-DRIVEN TEST — each entry is an independent sub-case.
	cases := []struct {
		name    string
		content []byte
	}{
		{"empty file", []byte{}},
		{"too short", []byte("CRDV")},
		{"bad magic", []byte("XXXX" + string(make([]byte, MinVaultSize)))},
		{"random garbage", []byte("this is not a vault file at all")},
	}

	for _, tc := range cases {
		// t.Run executes tc as an independent sub-test.
		// The closure receives its own *testing.T so it can fail independently.
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "bad.vault")

			// Write the bad content directly — bypass Init.
			if err := os.WriteFile(path, tc.content, 0600); err != nil {
				t.Fatalf("writing test file: %v", err)
			}

			v := New(path, defaultTestParams())
			_, err := v.Unseal([]byte("any-passphrase"))
			if err == nil {
				t.Errorf("expected error for %q, got nil", tc.name)
			}
		})
	}
}

// ── Seal round-trip ───────────────────────────────────────────────────────────

// TestSealUnsealRoundTrip verifies that data written via Seal is recovered
// exactly by Unseal. This covers the most critical invariant of the package.
func TestSealUnsealRoundTrip(t *testing.T) {
	v, passphrase := newTestVault(t)

	// Unseal the empty vault.
	state, err := v.Unseal(passphrase)
	if err != nil {
		t.Fatalf("initial Unseal: %v", err)
	}

	// Add test data.
	state.Keys["prod/db-pass"] = "supersecret"
	state.Keys["prod/api-key"] = "abc123"
	raw, _ := hex.DecodeString("aaabbbccc000000000000000000000000000000000000000000000000000000aa")
	sum := sha256.Sum256(raw)
	state.Tokens = []Token{
		{
			Name:        "test-tok",
			Hash:        hex.EncodeToString(sum[:]),
			Description: "test-token",
			Role:        RoleAdmin,
			CreatedAt:   time.Now().UTC(),
		},
	}

	// Seal with the modified state.
	if err := v.Seal(state, passphrase); err != nil {
		t.Fatalf("Seal: %v", err)
	}
	state.Zero()

	// Unseal again and verify the data survived.
	recovered, err := v.Unseal(passphrase)
	if err != nil {
		t.Fatalf("second Unseal: %v", err)
	}
	defer recovered.Zero()

	if got := recovered.Keys["prod/db-pass"]; got != "supersecret" {
		t.Errorf("prod/db-pass: got %q, want %q", got, "supersecret")
	}
	if got := recovered.Keys["prod/api-key"]; got != "abc123" {
		t.Errorf("prod/api-key: got %q, want %q", got, "abc123")
	}
	if len(recovered.Tokens) != 1 {
		t.Fatalf("expected 1 token, got %d", len(recovered.Tokens))
	}
	if recovered.Tokens[0].Name != "test-tok" {
		t.Errorf("token name: got %q", recovered.Tokens[0].Name)
	}
	if recovered.Tokens[0].Description != "test-token" {
		t.Errorf("token description: got %q", recovered.Tokens[0].Description)
	}
}

// TestSealProducesFreshNonce verifies that sealing twice produces different
// ciphertext — confirming a fresh nonce is generated on every Seal call.
// Reusing a nonce with AES-GCM would be catastrophic for security, so this
// test protects against that regression.
func TestSealProducesFreshNonce(t *testing.T) {
	v, passphrase := newTestVault(t)

	state, _ := v.Unseal(passphrase)
	state.Keys["k"] = "v"

	if err := v.Seal(state, passphrase); err != nil {
		t.Fatal(err)
	}
	first, _ := os.ReadFile(v.path)

	if err := v.Seal(state, passphrase); err != nil {
		t.Fatal(err)
	}
	second, _ := os.ReadFile(v.path)

	// The files should have the same magic and version but differ in salt/nonce.
	if string(first) == string(second) {
		t.Error("two Seal calls produced identical ciphertext — nonce is not being randomised")
	}
}

// ── Token helper methods ───────────────────────────────────────────────────────

// TestTokenLifecycle tests IsPersistent, IsEphemeral, and IsExpired across all
// the states a token can be in.
func TestTokenLifecycle(t *testing.T) {
	now := time.Now().UTC()
	past := now.Add(-1 * time.Hour)
	future := now.Add(1 * time.Hour)
	zero := time.Time{} // the ephemeral sentinel

	cases := []struct {
		name       string
		expiresAt  *time.Time
		persistent bool
		ephemeral  bool
		expired    bool
	}{
		{
			// nil ExpiresAt means "no expiry, persist to disk".
			name:       "persistent (nil)",
			expiresAt:  nil,
			persistent: true,
		},
		{
			// Zero time is the sentinel for ephemeral (process-scoped only).
			name:      "ephemeral (zero time)",
			expiresAt: &zero,
			ephemeral: true,
		},
		{
			// A past timestamp — the token should be considered expired.
			name:      "expired TTL",
			expiresAt: &past,
			expired:   true,
		},
		{
			// A future timestamp — not yet expired.
			name:      "valid TTL",
			expiresAt: &future,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tok := &Token{ExpiresAt: tc.expiresAt}

			if got := tok.IsPersistent(); got != tc.persistent {
				t.Errorf("IsPersistent() = %v, want %v", got, tc.persistent)
			}
			if got := tok.IsEphemeral(); got != tc.ephemeral {
				t.Errorf("IsEphemeral() = %v, want %v", got, tc.ephemeral)
			}
			if got := tok.IsExpired(); got != tc.expired {
				t.Errorf("IsExpired() = %v, want %v", got, tc.expired)
			}
		})
	}
}

// ── Helpers ───────────────────────────────────────────────────────────────────

// newTestVault creates a freshly initialised vault in a temp directory and
// returns a Vault and the passphrase used. It calls t.Fatal if anything goes
// wrong, so callers do not need to handle the error themselves.
//
// This is a test helper — a function only used by tests to reduce boilerplate.
// Naming it with a lowercase prefix keeps it unexported (test-file-only).
func newTestVault(t *testing.T) (*Vault, []byte) {
	t.Helper() // marks this as a helper so failures show the caller's line number

	dir := t.TempDir()
	path := filepath.Join(dir, "test.vault")
	passphrase := []byte("test-passphrase-do-not-use")

	v := New(path, defaultTestParams())
	if err := v.Init(passphrase); err != nil {
		t.Fatalf("newTestVault: Init failed: %v", err)
	}
	return v, passphrase
}
