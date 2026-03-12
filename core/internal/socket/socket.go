// cordova/core/internal/socket/socket.go

package socket

import (
	"cordova/core/ipc"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"os"
	"sync"
	"time"

	"cordova/core/internal/audit"
	"cordova/core/internal/auth"
	"cordova/core/internal/store"
	"cordova/core/internal/vault"
)

const version = "0.3.0"

// Server listens on a Unix domain socket and dispatches IPC commands from
// authenticated cordova-admin clients.
type Server struct {
	socketPath string
	store      *store.Store
	vault      *vault.Vault
	auditLog   *audit.Logger
	passphrase []byte
	writeMu    sync.Mutex
	auth       *auth.Authenticator
	sealCh     chan struct{}
	listener   net.Listener
}

func NewServer(
	socketPath string,
	s *store.Store,
	v *vault.Vault,
	al *audit.Logger,
	passphrase []byte,
) *Server {
	srv := &Server{
		socketPath: socketPath,
		store:      s,
		vault:      v,
		auditLog:   al,
		passphrase: passphrase,
		sealCh:     make(chan struct{}, 1),
	}
	srv.auth = auth.New(s, &srv.writeMu, srv.persist, al)
	return srv
}
func (s *Server) Start() error {
	_ = os.Remove(s.socketPath) //TODO log error

	ln, err := net.Listen("unix", s.socketPath)
	if err != nil {
		return fmt.Errorf("listening on %s: %w", s.socketPath, err)
	}
	s.listener = ln

	if err := os.Chmod(s.socketPath, 0600); err != nil {
		_ = ln.Close() //TODO log error
		return fmt.Errorf("setting socket permissions: %w", err)
	}

	s.auditLog.Log(audit.Entry{Event: audit.EventSocketStart, Source: s.socketPath})
	slog.Info("socket server started", "path", s.socketPath)

	go s.acceptLoop()
	return nil
}
func (s *Server) SealRequested() <-chan struct{} {
	return s.sealCh
}
func (s *Server) Stop() {
	if s.listener != nil {
		_ = s.listener.Close() //TODO log error
	}
	_ = os.Remove(s.socketPath) //TODO log error
	zeroBytes(s.passphrase)
	s.auditLog.Log(audit.Entry{Event: audit.EventSocketStop, Source: s.socketPath})
}
func (s *Server) acceptLoop() {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			return
		}
		go s.handleConn(conn)
	}
}
func (s *Server) handleConn(conn net.Conn) {
	defer func(conn net.Conn) {
		_ = conn.Close() //TODO log error
	}(conn)
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second)) //TODO log error

	var req ipc.Request
	if err := json.NewDecoder(conn).Decode(&req); err != nil {
		writeResp(conn, ipc.Response{OK: false, Error: "invalid request"})
		return
	}

	result := s.auth.Authenticate(req.Token, s.socketPath, req.Command)
	if !result.Allowed {
		writeResp(conn, ipc.Response{OK: false, Error: result.Err})
		return
	}
	s.store.TouchToken(result.Token.Name)

	writeResp(conn, s.dispatch(req))
}
func (s *Server) dispatch(req ipc.Request) ipc.Response {
	switch req.Command {
	case ipc.CmdKeyGet:
		return s.handleKeyGet(req.Params)
	case ipc.CmdKeySet:
		return s.handleKeySet(req.Params)
	case ipc.CmdKeyDelete:
		return s.handleKeyDelete(req.Params)
	case ipc.CmdKeyList:
		return s.handleKeyList()
	case ipc.CmdTokenAdd:
		return s.handleTokenAdd(req.Params)
	case ipc.CmdTokenList:
		return s.handleTokenList()
	case ipc.CmdTokenRevoke:
		return s.handleTokenRevoke(req.Params)
	case ipc.CmdTokenRevokeAll:
		return s.handleTokenRevokeAll()
	case ipc.CmdSeal:
		return s.handleSeal()
	case ipc.CmdStatus:
		return s.handleStatus()
	default:
		return errResp("unknown command: " + req.Command)
	}
}

// ── Handlers ──────────────────────────────────────────────────────────────────
func (s *Server) handleKeyGet(raw json.RawMessage) ipc.Response {
	var p ipc.KeyGetParams
	if err := json.Unmarshal(raw, &p); err != nil {
		return errResp("invalid params: " + err.Error())
	}
	value, err := s.store.GetKey(p.Name)
	if err != nil {
		return errResp(err.Error())
	}
	s.auditLog.Log(audit.Entry{Event: audit.EventKeyGet, Key: p.Name})
	return okResp(ipc.KeyGetData{Name: p.Name, Value: value})
}
func (s *Server) handleKeySet(raw json.RawMessage) ipc.Response {
	var p ipc.KeySetParams
	if err := json.Unmarshal(raw, &p); err != nil {
		return errResp("invalid params: " + err.Error())
	}

	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	_, getErr := s.store.GetKey(p.Name)
	isRotate := getErr == nil

	if err := s.store.SetKey(p.Name, p.Value); err != nil {
		return errResp(err.Error())
	}
	if err := s.persist(); err != nil {
		return errResp("persist failed: " + err.Error())
	}

	if isRotate {
		s.auditLog.Log(audit.Entry{Event: audit.EventKeyRotated, Key: p.Name})
	} else {
		s.auditLog.Log(audit.Entry{Event: audit.EventKeyAdded, Key: p.Name})
	}
	return okResp(ipc.AckData{Message: "ok"})
}
func (s *Server) handleKeyDelete(raw json.RawMessage) ipc.Response {
	var p ipc.KeyDeleteParams
	if err := json.Unmarshal(raw, &p); err != nil {
		return errResp("invalid params: " + err.Error())
	}

	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	if err := s.store.DeleteKey(p.Name); err != nil {
		return errResp(err.Error())
	}
	if err := s.persist(); err != nil {
		return errResp("persist failed: " + err.Error())
	}
	s.auditLog.Log(audit.Entry{Event: audit.EventKeyDeleted, Key: p.Name})
	return okResp(ipc.AckData{Message: "ok"})
}

// handleKeyList returns the names of all keys in the store. Read-only.
func (s *Server) handleKeyList() ipc.Response {
	keys, err := s.store.ListKeys()
	if err != nil {
		return errResp(err.Error())
	}
	if keys == nil {
		keys = []string{}
	}
	return okResp(ipc.KeyListData{Keys: keys})
}
func (s *Server) handleTokenAdd(raw json.RawMessage) ipc.Response {
	var p ipc.TokenAddParams
	if err := json.Unmarshal(raw, &p); err != nil {
		return errResp("invalid params: " + err.Error())
	}

	var expiresAt *time.Time
	switch p.ExpiresAt {
	case "", "persistent":
		expiresAt = nil
	case "ephemeral":
		expiresAt = vault.EphemeralExpiry()
	default:
		t, err := time.Parse(time.RFC3339, p.ExpiresAt)
		if err != nil {
			return errResp("invalid expires_at: expected \"ephemeral\" or RFC3339 timestamp")
		}
		if !t.After(time.Now().UTC()) {
			return errResp("invalid expires_at: timestamp must be in the future")
		}
		expiresAt = &t
	}

	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	secret, err := s.store.AddToken(p.Name, p.Description, expiresAt, p.CIDRs, p.Namespaces, p.Keys, p.Writable)
	if err != nil {
		return errResp(err.Error())
	}

	if expiresAt == nil || !expiresAt.IsZero() {
		if err := s.persist(); err != nil {
			return errResp("persist failed: " + err.Error())
		}
	}

	s.auditLog.Log(audit.Entry{
		Event: audit.EventTokenAdded,
		Extra: map[string]string{
			"name":        p.Name,
			"description": p.Description,
			"role":        p.Role,
			"expires_at":  p.ExpiresAt,
		},
	})
	return okResp(ipc.TokenAddData{
		Name:        p.Name,
		Secret:      secret,
		Description: p.Description,
		Role:        p.Role,
		ExpiresAt:   p.ExpiresAt,
		CIDRs:       p.CIDRs,
		Namespaces:  p.Namespaces,
		Keys:        p.Keys,
		Writable:    p.Writable,
	})
}
func (s *Server) handleTokenList() ipc.Response {
	tokens, err := s.store.ListTokens()
	if err != nil {
		return errResp(err.Error())
	}
	summaries := make([]ipc.TokenSummary, len(tokens))
	for i, t := range tokens {
		ts := ipc.TokenSummary{
			Name:        t.Name,
			Description: t.Description,
			CIDRs:       t.CIDRs,
			Namespaces:  t.Namespaces,
			Keys:        t.Keys,
			Writable:    t.Writable,
			CreatedAt:   t.CreatedAt.Format(time.RFC3339),
		}
		switch {
		case t.IsPersistent():
			ts.ExpiresAt = "persistent"
		case t.IsEphemeral():
			ts.ExpiresAt = "ephemeral"
		default:
			ts.ExpiresAt = t.ExpiresAt.Format(time.RFC3339)
		}
		if t.LastUsed != nil {
			ts.LastUsed = t.LastUsed.Format(time.RFC3339)
		}
		summaries[i] = ts
	}
	return okResp(ipc.TokenListData{Tokens: summaries})
}
func (s *Server) handleTokenRevoke(raw json.RawMessage) ipc.Response {
	var p ipc.TokenRevokeParams
	if err := json.Unmarshal(raw, &p); err != nil {
		return errResp("invalid params: " + err.Error())
	}

	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	if err := s.store.RevokeToken(p.Name); err != nil {
		return errResp(err.Error())
	}
	if err := s.persist(); err != nil {
		return errResp("persist failed: " + err.Error())
	}
	s.auditLog.Log(audit.Entry{
		Event: audit.EventTokenRevoked,
		Extra: map[string]string{"name": p.Name},
	})
	return okResp(ipc.AckData{Message: "ok"})
}
func (s *Server) handleTokenRevokeAll() ipc.Response {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	if err := s.store.RevokeAll(); err != nil {
		return errResp(err.Error())
	}
	if err := s.persist(); err != nil {
		return errResp("persist failed: " + err.Error())
	}
	s.auditLog.Log(audit.Entry{Event: audit.EventTokenRevokeAll})
	return okResp(ipc.AckData{Message: "all tokens revoked"})
}
func (s *Server) handleSeal() ipc.Response {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	if err := s.persist(); err != nil {
		return errResp("seal re-encrypt failed: " + err.Error())
	}

	s.auditLog.Log(audit.Entry{Event: audit.EventSealRequest})
	select {
	case s.sealCh <- struct{}{}:
	default:
	}
	return okResp(ipc.AckData{Message: "sealing"})
}
func (s *Server) handleStatus() ipc.Response {
	return okResp(ipc.StatusData{
		Sealed:  s.store.IsSealed(),
		Version: version,
	})
}
func (s *Server) persist() error {
	snap, err := s.store.Snapshot()
	if err != nil {
		return fmt.Errorf("snapshotting store: %w", err)
	}
	return s.vault.Seal(snap, s.passphrase)
}
func okResp(data any) ipc.Response {
	b, _ := json.Marshal(data)
	return ipc.Response{OK: true, Data: json.RawMessage(b)}
}
func errResp(msg string) ipc.Response {
	return ipc.Response{OK: false, Error: msg}
}
func writeResp(conn net.Conn, resp ipc.Response) {
	json.NewEncoder(conn).Encode(resp) //nolint:errcheck
}
func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
