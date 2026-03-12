// cordova/core/internal/auth/auth.go

package auth

import (
	"cordova/core/internal/audit"
	"cordova/core/internal/store"
	"cordova/core/internal/vault"
	"sync"
)

type Result struct {
	Allowed bool
	Token   *vault.Token
	Err     string
}

type Authenticator struct {
	store    *store.Store
	writeMu  *sync.Mutex
	persist  func() error
	auditLog *audit.Logger
}

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
		a.writeMu.Lock()
		_ = a.store.RevokeToken(tok.Name) //TODO log error
		_ = a.persist()                   //TODO log error
		a.writeMu.Unlock()
		a.auditLog.Log(audit.Entry{Event: audit.EventTokenExpired, Source: socketPath})
		return Result{Err: "token expired"}
	}
	a.auditLog.Log(audit.Entry{
		Event:   audit.EventAuthOK,
		TokenID: tok.Name,
		Source:  socketPath,
		Extra:   map[string]string{"command": command},
	})
	return Result{Allowed: true, Token: tok}
}
