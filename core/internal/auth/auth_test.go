// cordova/core/internal/auth/auth_test.go
//
// Tests for Authenticator. Because auth is its own package these tests run
// without starting a socket server — pure logic, fast, no I/O beyond a temp
// audit log file.

package auth

import (
	"path/filepath"
	"sync"
	"testing"
	"time"

	"cordova/core/internal/audit"
	"cordova/core/internal/store"
	"cordova/core/internal/vault"
)

// ── Helpers ───────────────────────────────────────────────────────────────────

// newTestAuth builds a fully wired Authenticator with a pre-loaded store.
// It returns the authenticator, the store (so tests can add tokens), and a
// cleanup function.
func newTestAuth(t *testing.T) (*Authenticator, *store.Store) {
	t.Helper()

	s := store.New()
	s.Load(&vault.State{
		Keys:   make(map[string]string),
		Tokens: []vault.Token{},
	})

	var mu sync.Mutex

	// A no-op persist for unit tests — we are testing auth decisions, not disk I/O.
	persist := func() error { return nil }

	al, err := audit.New(filepath.Join(t.TempDir(), "audit.log"))
	if err != nil {
		t.Fatalf("opening audit log: %v", err)
	}
	t.Cleanup(func() { al.Close() })

	return New(s, &mu, persist, al), s
}

// addToken is a test shortcut that adds a token to the store and returns the
// one-time secret. The name is fixed ("test-tok") since each test gets a
// fresh store instance.
func addToken(t *testing.T, s *store.Store, role vault.TokenRole, expiresAt *time.Time) string {
	t.Helper()
	secret, err := s.AddToken("test-tok", "test token", role, expiresAt, nil, nil, nil, false)
	if err != nil {
		t.Fatalf("addToken: %v", err)
	}
	return secret
}

// ── Denied cases ──────────────────────────────────────────────────────────────

func TestAuthenticate_EmptyToken(t *testing.T) {
	a, _ := newTestAuth(t)
	r := a.Authenticate("", "/run/test.sock", "status")
	if r.Allowed {
		t.Error("empty token should be denied")
	}
}

func TestAuthenticate_UnknownToken(t *testing.T) {
	a, _ := newTestAuth(t)
	r := a.Authenticate("not-a-real-token", "/run/test.sock", "status")
	if r.Allowed {
		t.Error("unknown token should be denied")
	}
	if r.Err == "" {
		t.Error("denied result should carry an error message")
	}
}

func TestAuthenticate_AccessRoleRejected(t *testing.T) {
	// Access-role tokens are reserved for future HTTP/SSH consumers and must
	// never be accepted at the admin socket.
	a, s := newTestAuth(t)
	id := addToken(t, s, vault.RoleAccess, nil)

	r := a.Authenticate(id, "/run/test.sock", "key.get")
	if r.Allowed {
		t.Error("access-role token should be denied at admin socket")
	}
}

// ── Expired cases ─────────────────────────────────────────────────────────────

func TestAuthenticate_ExpiredToken_Denied(t *testing.T) {
	a, s := newTestAuth(t)
	past := time.Now().UTC().Add(-1 * time.Hour)
	id := addToken(t, s, vault.RoleAdmin, &past)

	r := a.Authenticate(id, "/run/test.sock", "status")
	if r.Allowed {
		t.Error("expired token should not be allowed")
	}
	if r.Err != "token expired" {
		t.Errorf("expected 'token expired', got %q", r.Err)
	}
}

func TestAuthenticate_ExpiredToken_RevokedAfterUse(t *testing.T) {
	// After an expired token is used once, it should be deleted from the store.
	// A second attempt with the same ID should get "unauthorized", not "token expired".
	a, s := newTestAuth(t)
	past := time.Now().UTC().Add(-1 * time.Hour)
	id := addToken(t, s, vault.RoleAdmin, &past)

	// First attempt: expired.
	r1 := a.Authenticate(id, "/run/test.sock", "status")
	if r1.Err != "token expired" {
		t.Fatalf("first attempt: expected 'token expired', got %q", r1.Err)
	}

	// Second attempt with the same ID: token is gone, should be "unauthorized".
	r2 := a.Authenticate(id, "/run/test.sock", "status")
	if r2.Err != "unauthorized" {
		t.Errorf("second attempt: expected 'unauthorized', got %q", r2.Err)
	}
}

// ── Allowed cases ─────────────────────────────────────────────────────────────

func TestAuthenticate_ValidAdminToken(t *testing.T) {
	a, s := newTestAuth(t)
	id := addToken(t, s, vault.RoleAdmin, nil) // persistent

	r := a.Authenticate(id, "/run/test.sock", "key.list")
	if !r.Allowed {
		t.Errorf("valid admin token should be allowed, got err: %s", r.Err)
	}
	if r.Token == nil {
		t.Error("allowed result must carry the resolved token")
	}
	if r.Token.Name != "test-tok" {
		t.Errorf("token name mismatch: got %q, want %q", r.Token.Name, "test-tok")
	}
}

func TestAuthenticate_EphemeralAdminToken(t *testing.T) {
	// Ephemeral tokens (zero-time sentinel) are process-scoped and never
	// written to disk, but they are valid for the lifetime of the process.
	a, s := newTestAuth(t)
	ephemeral := vault.EphemeralExpiry()
	id := addToken(t, s, vault.RoleAdmin, ephemeral)

	r := a.Authenticate(id, "/run/test.sock", "token.list")
	if !r.Allowed {
		t.Errorf("ephemeral admin token should be allowed, got: %s", r.Err)
	}
}

func TestAuthenticate_TTLToken_NotYetExpired(t *testing.T) {
	a, s := newTestAuth(t)
	future := time.Now().UTC().Add(1 * time.Hour)
	id := addToken(t, s, vault.RoleAdmin, &future)

	r := a.Authenticate(id, "/run/test.sock", "status")
	if !r.Allowed {
		t.Errorf("TTL token before expiry should be allowed, got: %s", r.Err)
	}
}
