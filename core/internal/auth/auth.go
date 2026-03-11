// cordova/core/internal/auth/auth.go
//
// Package auth is the single place in the codebase that decides whether a
// request is permitted to proceed. It handles token lookup, expiry cleanup,
// and role checks. It owns all side effects of those decisions (revoking
// expired tokens, persisting the change, writing audit entries).
//
// The socket layer is purely transport: it reads a request off the wire,
// calls Authenticate, and writes the result back. It never makes auth
// decisions itself.

package auth

import (
	"sync"

	"cordova/core/internal/audit"
	"cordova/core/internal/store"
	"cordova/core/internal/vault"
)

// Result is returned by Authenticate. The socket layer reads Allowed and Err
// to build its response; it never inspects the token itself for auth purposes.
type Result struct {
	// Allowed is true when the request may proceed.
	Allowed bool

	// Token is the resolved vault.Token. Non-nil only when Allowed is true.
	// The socket layer uses it to update LastUsed via store.TouchToken.
	Token *vault.Token

	// Err is the human-readable error message to return to the client when
	// Allowed is false. Never leaks internal details (wrong passphrase vs
	// missing token both become "unauthorized").
	Err string
}

// Authenticator makes and enforces authentication decisions. It is the only
// type permitted to read tokens for auth purposes; everything else in the
// codebase should go through it.
type Authenticator struct {
	// store provides token lookup and revocation.
	store *store.Store

	// writeMu is the shared mutex that serialises all store mutations and
	// disk writes. Owned by socket.Server; auth borrows a pointer so that
	// expired-token cleanup is serialised with the write handlers.
	//
	// WHY A POINTER TO A MUTEX?
	// In Go a sync.Mutex must not be copied after first use. Passing it by
	// pointer ensures auth and the socket handlers share the exact same lock
	// instance, not independent copies. Using a pointer here is idiomatic
	// when two collaborating types need to share one mutex.
	writeMu *sync.Mutex

	// persist writes the current store state to the encrypted vault file.
	// Must only be called with writeMu held. Provided as a function so auth
	// does not need a direct reference to the vault or passphrase.
	persist func() error

	// auditLog records auth events. Auth is the right owner because it is
	// the only layer that knows the full decision — denied/expired/ok — and
	// the token that was involved.
	auditLog *audit.Logger
}

// New constructs an Authenticator. writeMu must be a pointer to the mutex
// owned by the caller; persist must be safe to call with writeMu held.
func New(
	s *store.Store,
	writeMu *sync.Mutex,
	persist func() error,
	al *audit.Logger,
) *Authenticator {
	return &Authenticator{
		store:    s,
		writeMu:  writeMu,
		persist:  persist,
		auditLog: al,
	}
}

// Authenticate is the single entry point for all auth decisions. It evaluates
// the request in three steps:
//
//  1. Lookup  — does a token with this ID exist?
//  2. Expiry  — has the token passed its TTL? If so, revoke it and persist.
//  3. Role    — is the token's role permitted on this socket? (admin only for now)
//
// socketPath and command are used only for audit log entries.
func (a *Authenticator) Authenticate(tokenValue, socketPath, command string) Result {
	if tokenValue == "" {
		a.auditLog.Log(audit.Entry{Event: audit.EventAuthDenied, Source: socketPath})
		return Result{Err: "unauthorized"}
	}

	tok, err := a.store.FindToken(tokenValue)
	if err != nil {
		a.auditLog.Log(audit.Entry{Event: audit.EventAuthDenied, Source: socketPath})
		return Result{Err: "unauthorized"}
	}

	if tok.IsExpired() {
		// The token exists but its TTL has elapsed. Revoke it now so that
		// any subsequent request with the same secret gets "unauthorized"
		// rather than "token expired" (the specific error is returned once).
		a.writeMu.Lock()
		a.store.RevokeToken(tok.Name) //nolint:errcheck
		a.persist()                   //nolint:errcheck — best-effort; stale token still unusable
		a.writeMu.Unlock()

		a.auditLog.Log(audit.Entry{Event: audit.EventTokenExpired, Source: socketPath})
		return Result{Err: "token expired"}
	}

	// Only admin-role tokens are accepted at the admin socket.
	// Access-role tokens are reserved for future cordova-http / cordova-ssh.
	if tok.Role != vault.RoleAdmin {
		a.auditLog.Log(audit.Entry{Event: audit.EventAuthDenied, Source: socketPath})
		return Result{Err: "unauthorized"}
	}

	a.auditLog.Log(audit.Entry{
		Event:   audit.EventAuthOK,
		TokenID: tok.Name,
		Source:  socketPath,
		Extra:   map[string]string{"command": command},
	})
	return Result{Allowed: true, Token: tok}
}
