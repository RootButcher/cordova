// cordova/core/internal/socket/socket.go
//
// Package socket is a pure transport layer. It accepts connections on a Unix
// domain socket, reads one JSON request per connection, delegates the auth
// decision entirely to the auth package, dispatches the command to the
// appropriate handler, and writes the response. It makes no auth decisions
// itself and holds no auth state.

package socket

import (
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
	// socketPath is the filesystem path of the Unix domain socket.
	socketPath string

	// store is the in-memory vault state used for key/token operations.
	store *store.Store

	// vault is used to persist state after mutating commands.
	vault *vault.Vault

	// auditLog records all security-relevant events.
	auditLog *audit.Logger

	// passphrase is retained from unseal to re-encrypt the vault on mutations.
	// It is zeroed in Stop.
	passphrase []byte

	// writeMu serialises all operations that mutate the store and write to
	// disk. It covers the entire "change memory → snapshot → seal to disk"
	// sequence so that concurrent connections cannot interleave their writes
	// and produce an inconsistent vault file.
	//
	// auth.Authenticator holds a pointer to this mutex so that expired-token
	// cleanup (revoke + persist) is serialised with all other write operations.
	writeMu sync.Mutex

	// auth is the single authority for all authentication decisions.
	// The socket layer calls it and acts on the result; it never inspects
	// token values or makes role decisions itself.
	auth *auth.Authenticator

	// sealCh receives a signal when a client sends the seal command, allowing
	// the main goroutine to initiate a clean shutdown.
	sealCh chan struct{}

	// listener is the active network listener; closed by Stop.
	listener net.Listener
}

// NewServer constructs a Server. passphrase ownership is transferred to the
// server — the caller must not use or zero it afterwards. It is zeroed in Stop.
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
	// auth borrows a pointer to writeMu so that expired-token cleanup is
	// serialised with the write handlers. srv.persist is a bound method value:
	// calling it is equivalent to srv.persist() with the correct receiver.
	srv.auth = auth.New(s, &srv.writeMu, srv.persist, al)
	return srv
}

// Start removes any stale socket file, binds the listener, sets permissions to
// 0600, and begins accepting connections in a background goroutine.
func (s *Server) Start() error {
	os.Remove(s.socketPath)

	ln, err := net.Listen("unix", s.socketPath)
	if err != nil {
		return fmt.Errorf("listening on %s: %w", s.socketPath, err)
	}
	s.listener = ln

	if err := os.Chmod(s.socketPath, 0600); err != nil {
		ln.Close()
		return fmt.Errorf("setting socket permissions: %w", err)
	}

	s.auditLog.Log(audit.Entry{Event: audit.EventSocketStart, Source: s.socketPath})
	slog.Info("socket server started", "path", s.socketPath)

	go s.acceptLoop()
	return nil
}

// SealRequested returns a channel that receives a value when a client sends
// the seal command. The main goroutine should listen on this channel and call
// Stop when it fires.
func (s *Server) SealRequested() <-chan struct{} {
	return s.sealCh
}

// Stop closes the listener, removes the socket file, and zeros the passphrase
// from memory.
func (s *Server) Stop() {
	if s.listener != nil {
		s.listener.Close()
	}
	os.Remove(s.socketPath)
	zeroBytes(s.passphrase)
	s.auditLog.Log(audit.Entry{Event: audit.EventSocketStop, Source: s.socketPath})
}

// acceptLoop accepts incoming connections until the listener is closed.
// Each connection is handled in its own goroutine.
func (s *Server) acceptLoop() {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			return
		}
		go s.handleConn(conn)
	}
}

// handleConn is the transport handler. It sets a deadline, decodes one JSON
// request, delegates to auth, and writes the response. It does not make any
// auth decisions itself.
func (s *Server) handleConn(conn net.Conn) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(30 * time.Second)) //nolint:errcheck

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

	// Update last-used timestamp. This is a lightweight in-memory update
	// that does not require writeMu (it does not touch the vault file).
	s.store.TouchToken(result.Token.Name)

	writeResp(conn, s.dispatch(req))
}

// dispatch routes a validated request to the appropriate handler.
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

// handleKeyGet retrieves a key value from the store.
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

// handleKeySet adds or rotates a key. writeMu ensures the store mutation and
// disk write are atomic.
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

// handleKeyDelete removes a key from the store and persists the change.
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

// handleTokenAdd creates a new token and persists it (unless ephemeral).
func (s *Server) handleTokenAdd(raw json.RawMessage) ipc.Response {
	var p ipc.TokenAddParams
	if err := json.Unmarshal(raw, &p); err != nil {
		return errResp("invalid params: " + err.Error())
	}

	role := vault.TokenRole(p.Role)
	if role != vault.RoleAdmin && role != vault.RoleAccess {
		return errResp("invalid role: must be \"admin\" or \"access\"")
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

	secret, err := s.store.AddToken(p.Name, p.Description, role, expiresAt, p.CIDRs, p.Namespaces, p.Keys, p.Writable)
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

// handleTokenList returns a summary of all tokens in the store. Read-only.
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
			Role:        string(t.Role),
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

// handleTokenRevoke removes a single token by name and persists the change.
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

// handleTokenRevokeAll removes every token and persists the change.
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

// handleSeal re-encrypts the vault with a fresh salt and nonce under writeMu,
// then signals the main goroutine to shut down.
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

// handleStatus returns the current sealed/unsealed state and daemon version.
// Read-only.
func (s *Server) handleStatus() ipc.Response {
	return okResp(ipc.StatusData{
		Sealed:  s.store.IsSealed(),
		Version: version,
	})
}

// ── Helpers ───────────────────────────────────────────────────────────────────

// persist snapshots the current store state and re-encrypts it to disk.
// Must be called with writeMu held.
func (s *Server) persist() error {
	snap, err := s.store.Snapshot()
	if err != nil {
		return fmt.Errorf("snapshotting store: %w", err)
	}
	return s.vault.Seal(snap, s.passphrase)
}

// okResp encodes data as JSON and returns a successful Response.
func okResp(data any) ipc.Response {
	b, _ := json.Marshal(data)
	return ipc.Response{OK: true, Data: json.RawMessage(b)}
}

// errResp returns a failed Response with a human-readable error message.
func errResp(msg string) ipc.Response {
	return ipc.Response{OK: false, Error: msg}
}

// writeResp encodes resp as JSON and writes it to conn.
func writeResp(conn net.Conn, resp ipc.Response) {
	json.NewEncoder(conn).Encode(resp) //nolint:errcheck
}

// zeroBytes overwrites b with zeros to clear sensitive material from memory.
func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
