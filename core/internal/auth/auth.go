// cordova/core/internal/auth/auth.go

package auth

import (
	"log/slog"
	"sync"

	"cordova/core/internal/audit"
	"cordova/core/internal/config"
	"cordova/core/internal/store"
	"cordova/core/internal/vault"
)

// Result is returned by Authenticate and carries the outcome of an auth check.
type Result struct {
	Allowed        bool
	User           *vault.User
	Token          *vault.Token
	EffectiveScope config.SocketScope
	Err            string
}

// Authenticator validates credentials against the user store.
type Authenticator struct {
	userStore *store.UserStore
	writeMu   *sync.Mutex
	persist   func() error
	auditLog  *audit.Logger
}

// New creates an Authenticator.
func New(
	us *store.UserStore,
	writeMu *sync.Mutex,
	persist func() error,
	al *audit.Logger,
) *Authenticator {
	return &Authenticator{
		userStore: us,
		writeMu:   writeMu,
		persist:   persist,
		auditLog:  al,
	}
}

// Authenticate looks up the user by username, validates the token, checks
// expiry, and computes the effective scope as the intersection of the user's
// permissions and the socket's scope.
func (a *Authenticator) Authenticate(
	username, tokenValue, socketPath, command string,
	scope config.SocketScope,
) Result {
	if username == "" || tokenValue == "" {
		a.auditLog.Log(audit.Entry{Event: audit.EventAuthDenied, Source: socketPath})
		return Result{Err: "unauthorized"}
	}

	user, tok, err := a.userStore.FindToken(username, tokenValue)
	if err != nil {
		a.auditLog.Log(audit.Entry{Event: audit.EventAuthDenied, Source: socketPath})
		return Result{Err: "unauthorized"}
	}

	if tok.IsExpired() {
		a.writeMu.Lock()
		if err := a.userStore.RevokeToken(username, tok.Name); err != nil {
			slog.Warn("failed to revoke expired token", "user", username, "token", tok.Name, "err", err)
		}
		if err := a.persist(); err != nil {
			slog.Warn("failed to persist after revoking expired token", "err", err)
		}
		a.writeMu.Unlock()
		a.auditLog.Log(audit.Entry{Event: audit.EventTokenExpired, Source: socketPath})
		return Result{Err: "token expired"}
	}

	effectiveScope := intersectScope(*user, scope)

	a.auditLog.Log(audit.Entry{
		Event:   audit.EventAuthOK,
		TokenID: tok.Name,
		Source:  socketPath,
		Extra:   map[string]string{"command": command, "user": username},
	})
	return Result{
		Allowed:        true,
		User:           user,
		Token:          tok,
		EffectiveScope: effectiveScope,
	}
}

// intersectScope computes the effective scope as the intersection of the user's
// permissions and the socket's declared scope.
func intersectScope(user vault.User, socket config.SocketScope) config.SocketScope {
	if socket.Unrestricted {
		return config.SocketScope{Unrestricted: true}
	}
	effective := config.SocketScope{
		Writable: socket.Writable && user.Writable,
	}
	// Namespaces: intersection of socket list and user list.
	effective.Namespaces = intersectSlice(user.Namespaces, socket.Namespaces)
	effective.Keys = intersectSlice(user.Keys, socket.Keys)
	return effective
}

// intersectSlice returns elements present in both a and b.
// If either slice is nil (unrestricted), the other slice is returned as-is.
func intersectSlice(a, b []string) []string {
	if a == nil {
		return b
	}
	if b == nil {
		return a
	}
	set := make(map[string]struct{}, len(b))
	for _, v := range b {
		set[v] = struct{}{}
	}
	var out []string
	for _, v := range a {
		if _, ok := set[v]; ok {
			out = append(out, v)
		}
	}
	return out
}
