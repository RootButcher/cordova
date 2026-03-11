// cordova/core/internal/socket/socket_test.go
//
// Integration tests for the socket server. These tests start a real Server,
// connect to it over a real Unix domain socket, and verify the responses.
//
// INTEGRATION TEST vs UNIT TEST
// ------------------------------
// A unit test exercises one small, isolated function (like store.SetKey).
// An integration test exercises multiple layers at once — here we test the
// full path: client connects → server authenticates → handler runs → response
// sent back. This catches bugs that only appear when the parts are combined.
//
// UNIX DOMAIN SOCKETS
// -------------------
// A Unix domain socket is like a TCP socket but lives on the filesystem as a
// special file. Connections only work on the same machine. Cordova uses them
// because they can be permission-restricted with chmod (0600), unlike TCP.
//
// To connect: net.Dial("unix", "/path/to/socket")
// To write:   json.NewEncoder(conn).Encode(request)
// To read:    json.NewDecoder(conn).Decode(&response)
//
// TESTING WITH REAL FILES
// -----------------------
// t.TempDir() returns a unique temporary directory for each test. Go removes
// it automatically after the test finishes, so you never have to clean up
// leftover socket files manually.

package socket

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"cordova/core/internal/audit"
	"cordova/core/internal/store"
	"cordova/core/internal/vault"
	"cordova/core/ipc"
)

// ── Test helpers ──────────────────────────────────────────────────────────────

// testServer builds a fully wired Server with a real vault, real store, and a
// temp audit log. It returns the server and an admin token that can be used to
// authenticate requests.
//
// Calling t.Cleanup registers the shutdown to run automatically when the test
// finishes — you do not need to defer srv.Stop() in every test.
// tokenHash computes the SHA-256 hash of a hex-encoded token secret and
// returns it as a hex string. This mirrors what store.FindToken does
// internally so we can pre-populate a vault with a known token.
func tokenHash(secret string) string {
	raw, _ := hex.DecodeString(secret)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func testServer(t *testing.T) (srv *Server, adminToken string) {
	t.Helper()

	dir := t.TempDir()
	vaultPath := filepath.Join(dir, "test.vault")
	auditPath := filepath.Join(dir, "audit.log")
	socketPath := filepath.Join(dir, "test.sock")
	passphrase := []byte("test-pass")

	// adminToken must be valid hex so store.FindToken can decode it.
	// We store the SHA-256 hash of its decoded bytes in the vault.
	adminToken = "0000000000000000000000000000000000000000000000000000000000000001"
	now := time.Now().UTC()
	initialState := &vault.State{
		Keys: make(map[string]string),
		Tokens: []vault.Token{
			{
				Name:        "test-admin",
				Hash:        tokenHash(adminToken),
				Description: "test admin token",
				Role:        vault.RoleAdmin,
				CreatedAt:   now,
			},
		},
	}

	v := vault.New(vaultPath, vault.KDFParams{Time: 1, Memory: 64, Threads: 1})
	if err := v.Seal(initialState, passphrase); err != nil {
		t.Fatalf("sealing test vault: %v", err)
	}

	state, err := v.Unseal(passphrase)
	if err != nil {
		t.Fatalf("unsealing test vault: %v", err)
	}

	s := store.New()
	s.Load(state)

	al, err := audit.New(auditPath)
	if err != nil {
		t.Fatalf("opening audit log: %v", err)
	}

	// Make a copy of the passphrase — NewServer takes ownership and zeros it.
	passCopy := make([]byte, len(passphrase))
	copy(passCopy, passphrase)

	srv = NewServer(socketPath, s, v, al, passCopy)
	if err := srv.Start(); err != nil {
		t.Fatalf("starting server: %v", err)
	}

	// t.Cleanup runs after the test, whether it passes or fails.
	// This is cleaner than defer because it runs even when the test calls
	// t.Fatal (which stops the current goroutine via runtime.Goexit).
	t.Cleanup(func() {
		srv.Stop()
		al.Close()
	})

	return srv, adminToken
}

// sendRequest dials the socket, sends one JSON request, and returns the decoded
// response. It is the test equivalent of the cordova-admin client.
func sendRequest(t *testing.T, socketPath string, req ipc.Request) ipc.Response {
	t.Helper()

	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		t.Fatalf("dialing socket: %v", err)
	}
	defer conn.Close()

	if err := json.NewEncoder(conn).Encode(req); err != nil {
		t.Fatalf("encoding request: %v", err)
	}

	var resp ipc.Response
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	return resp
}

// ── Authentication ────────────────────────────────────────────────────────────

// TestAuth_ValidToken verifies that a valid admin token is accepted.
func TestAuth_ValidToken(t *testing.T) {
	srv, adminToken := testServer(t)

	resp := sendRequest(t, srv.socketPath, ipc.Request{
		Token:   adminToken,
		Command: ipc.CmdStatus,
	})

	if !resp.OK {
		t.Errorf("expected OK=true, got error: %s", resp.Error)
	}
}

// TestAuth_InvalidToken verifies that an unknown token is rejected.
func TestAuth_InvalidToken(t *testing.T) {
	srv, _ := testServer(t)

	resp := sendRequest(t, srv.socketPath, ipc.Request{
		Token:   "not-a-real-token",
		Command: ipc.CmdStatus,
	})

	if resp.OK {
		t.Error("expected OK=false for invalid token, got true")
	}
}

// TestAuth_EmptyToken verifies that an empty token is rejected.
// This guards against the "empty string matches nothing" edge case.
func TestAuth_EmptyToken(t *testing.T) {
	srv, _ := testServer(t)

	resp := sendRequest(t, srv.socketPath, ipc.Request{
		Token:   "",
		Command: ipc.CmdStatus,
	})

	if resp.OK {
		t.Error("expected OK=false for empty token, got true")
	}
}

// Note: TTL token expiry logic is tested in store_test.go.
// The socket layer is only responsible for transport — whether a token is
// expired (and what to do about it) is the concern of the auth layer, not
// the socket layer. See TestExpiredTokenIsFound and TestExpiredTokenRevokedOnUse
// in store_test.go.

// ── Status ────────────────────────────────────────────────────────────────────

// TestHandleStatus verifies the status response structure.
func TestHandleStatus(t *testing.T) {
	srv, adminToken := testServer(t)

	resp := sendRequest(t, srv.socketPath, ipc.Request{
		Token:   adminToken,
		Command: ipc.CmdStatus,
	})

	if !resp.OK {
		t.Fatalf("status failed: %s", resp.Error)
	}

	var data ipc.StatusData
	if err := json.Unmarshal(resp.Data, &data); err != nil {
		t.Fatalf("decoding status data: %v", err)
	}

	// A running server should report the vault as unsealed.
	if data.Sealed {
		t.Error("expected Sealed=false for a running server")
	}
	if data.Version == "" {
		t.Error("expected non-empty version string")
	}
}

// ── Key operations ────────────────────────────────────────────────────────────

// TestKeySetGetDelete verifies the full key lifecycle over the socket.
func TestKeySetGetDelete(t *testing.T) {
	srv, adminToken := testServer(t)

	// Helper to build a request with the admin token.
	req := func(cmd string, params any) ipc.Request {
		b, _ := json.Marshal(params)
		return ipc.Request{Token: adminToken, Command: cmd, Params: json.RawMessage(b)}
	}

	// Set a key.
	resp := sendRequest(t, srv.socketPath, req(ipc.CmdKeySet, ipc.KeySetParams{
		Name: "prod/db-pass", Value: "s3cr3t",
	}))
	if !resp.OK {
		t.Fatalf("key.set failed: %s", resp.Error)
	}

	// Get the key back.
	resp = sendRequest(t, srv.socketPath, req(ipc.CmdKeyGet, ipc.KeyGetParams{
		Name: "prod/db-pass",
	}))
	if !resp.OK {
		t.Fatalf("key.get failed: %s", resp.Error)
	}

	var got ipc.KeyGetData
	if err := json.Unmarshal(resp.Data, &got); err != nil {
		t.Fatalf("decoding key.get data: %v", err)
	}
	if got.Value != "s3cr3t" {
		t.Errorf("key.get: got %q, want %q", got.Value, "s3cr3t")
	}

	// List keys — should contain our key.
	resp = sendRequest(t, srv.socketPath, ipc.Request{Token: adminToken, Command: ipc.CmdKeyList})
	if !resp.OK {
		t.Fatalf("key.list failed: %s", resp.Error)
	}
	var listData ipc.KeyListData
	json.Unmarshal(resp.Data, &listData) //nolint:errcheck
	found := false
	for _, k := range listData.Keys {
		if k == "prod/db-pass" {
			found = true
		}
	}
	if !found {
		t.Error("key.list did not return the key we set")
	}

	// Delete the key.
	resp = sendRequest(t, srv.socketPath, req(ipc.CmdKeyDelete, ipc.KeyDeleteParams{
		Name: "prod/db-pass",
	}))
	if !resp.OK {
		t.Fatalf("key.delete failed: %s", resp.Error)
	}

	// Getting the deleted key should now fail.
	resp = sendRequest(t, srv.socketPath, req(ipc.CmdKeyGet, ipc.KeyGetParams{
		Name: "prod/db-pass",
	}))
	if resp.OK {
		t.Error("expected key.get to fail after delete")
	}
}

// TestKeyGetMissing verifies the error response for an unknown key.
func TestKeyGetMissing(t *testing.T) {
	srv, adminToken := testServer(t)

	b, _ := json.Marshal(ipc.KeyGetParams{Name: "does/not/exist"})
	resp := sendRequest(t, srv.socketPath, ipc.Request{
		Token:   adminToken,
		Command: ipc.CmdKeyGet,
		Params:  json.RawMessage(b),
	})

	if resp.OK {
		t.Error("expected OK=false for missing key, got true")
	}
}

// ── Token operations ──────────────────────────────────────────────────────────

// TestTokenAddAndList verifies creating a token and seeing it in the list.
func TestTokenAddAndList(t *testing.T) {
	srv, adminToken := testServer(t)

	b, _ := json.Marshal(ipc.TokenAddParams{
		Name:        "ci-runner",
		Description: "new CI token",
		Role:        "admin",
	})
	resp := sendRequest(t, srv.socketPath, ipc.Request{
		Token:   adminToken,
		Command: ipc.CmdTokenAdd,
		Params:  json.RawMessage(b),
	})
	if !resp.OK {
		t.Fatalf("token.add failed: %s", resp.Error)
	}

	var added ipc.TokenAddData
	if err := json.Unmarshal(resp.Data, &added); err != nil {
		t.Fatalf("decoding token.add data: %v", err)
	}
	if added.Name != "ci-runner" {
		t.Errorf("expected name %q, got %q", "ci-runner", added.Name)
	}
	if added.Secret == "" {
		t.Error("expected non-empty token secret")
	}

	// List tokens — should see both the original admin token and the new one.
	resp = sendRequest(t, srv.socketPath, ipc.Request{
		Token:   adminToken,
		Command: ipc.CmdTokenList,
	})
	if !resp.OK {
		t.Fatalf("token.list failed: %s", resp.Error)
	}
	var listData ipc.TokenListData
	json.Unmarshal(resp.Data, &listData) //nolint:errcheck
	if len(listData.Tokens) < 2 {
		t.Errorf("expected at least 2 tokens, got %d", len(listData.Tokens))
	}
}

// TestTokenRevoke verifies that a revoked token can no longer authenticate.
func TestTokenRevoke(t *testing.T) {
	srv, adminToken := testServer(t)

	// Create a second admin token.
	b, _ := json.Marshal(ipc.TokenAddParams{Name: "to-revoke", Description: "revoke target", Role: "admin"})
	addResp := sendRequest(t, srv.socketPath, ipc.Request{
		Token:   adminToken,
		Command: ipc.CmdTokenAdd,
		Params:  json.RawMessage(b),
	})
	if !addResp.OK {
		t.Fatalf("token.add: %s", addResp.Error)
	}

	var added ipc.TokenAddData
	json.Unmarshal(addResp.Data, &added) //nolint:errcheck

	// Revoke it by name.
	rb, _ := json.Marshal(ipc.TokenRevokeParams{Name: added.Name})
	revokeResp := sendRequest(t, srv.socketPath, ipc.Request{
		Token:   adminToken,
		Command: ipc.CmdTokenRevoke,
		Params:  json.RawMessage(rb),
	})
	if !revokeResp.OK {
		t.Fatalf("token.revoke: %s", revokeResp.Error)
	}

	// The revoked token's secret must now be rejected.
	resp := sendRequest(t, srv.socketPath, ipc.Request{
		Token:   added.Secret,
		Command: ipc.CmdStatus,
	})
	if resp.OK {
		t.Error("revoked token was still accepted — revoke did not work")
	}
}

// ── Unknown command ───────────────────────────────────────────────────────────

// TestUnknownCommand verifies that an unrecognised command returns an error
// rather than panicking or succeeding silently.
func TestUnknownCommand(t *testing.T) {
	srv, adminToken := testServer(t)

	resp := sendRequest(t, srv.socketPath, ipc.Request{
		Token:   adminToken,
		Command: "does.not.exist",
	})

	if resp.OK {
		t.Error("expected OK=false for unknown command, got true")
	}
}

// ── Vault persistence ─────────────────────────────────────────────────────────

// TestPersistenceAfterKeySet verifies that a key written via the socket survives
// a server restart (i.e. that persist() was actually called and the vault file
// was updated).
//
// This is the most important integration test: it confirms that the
// "store mutate → snapshot → seal to disk" sequence works end-to-end.
func TestPersistenceAfterKeySet(t *testing.T) {
	dir := t.TempDir()
	vaultPath := filepath.Join(dir, "persist.vault")
	auditPath := filepath.Join(dir, "audit.log")
	passphrase := []byte("persist-test-pass")
	// Valid 64-char hex so store.FindToken can decode it.
	adminToken := "0000000000000000000000000000000000000000000000000000000000000002"

	// ── First server instance ──────────────────────────────────────────────
	buildAndStart := func() (*Server, func()) {
		initialState := &vault.State{
			Keys: make(map[string]string),
			Tokens: []vault.Token{{
				Name:        "persist-admin",
				Hash:        tokenHash(adminToken),
				Description: "persist admin token",
				Role:        vault.RoleAdmin,
				CreatedAt:   time.Now().UTC(),
			}},
		}
		v := vault.New(vaultPath, vault.KDFParams{Time: 1, Memory: 64, Threads: 1})

		// Only seal on first call (file does not exist yet).
		if _, err := os.Stat(vaultPath); os.IsNotExist(err) {
			v.Seal(initialState, passphrase) //nolint:errcheck
		}

		state, _ := v.Unseal(passphrase)
		s := store.New()
		s.Load(state)
		al, _ := audit.New(auditPath)
		passCopy := make([]byte, len(passphrase))
		copy(passCopy, passphrase)
		srv := NewServer(filepath.Join(dir, "persist.sock"), s, v, al, passCopy)
		srv.Start() //nolint:errcheck

		stop := func() { srv.Stop(); al.Close() }
		return srv, stop
	}

	srv1, stop1 := buildAndStart()

	// Write a key via the first server instance.
	b, _ := json.Marshal(ipc.KeySetParams{Name: "ns/secret", Value: "hello"})
	resp := sendRequest(t, srv1.socketPath, ipc.Request{
		Token:   adminToken,
		Command: ipc.CmdKeySet,
		Params:  json.RawMessage(b),
	})
	if !resp.OK {
		t.Fatalf("key.set on first server: %s", resp.Error)
	}

	stop1() // simulate daemon restart

	// ── Second server instance — reads the same vault file ─────────────────
	srv2, stop2 := buildAndStart()
	t.Cleanup(stop2)

	b2, _ := json.Marshal(ipc.KeyGetParams{Name: "ns/secret"})
	resp2 := sendRequest(t, srv2.socketPath, ipc.Request{
		Token:   adminToken,
		Command: ipc.CmdKeyGet,
		Params:  json.RawMessage(b2),
	})
	if !resp2.OK {
		t.Fatalf("key.get on second server: %s", resp2.Error)
	}

	var got ipc.KeyGetData
	json.Unmarshal(resp2.Data, &got) //nolint:errcheck
	if got.Value != "hello" {
		t.Errorf("after restart: got %q, want %q", got.Value, "hello")
	}
}
