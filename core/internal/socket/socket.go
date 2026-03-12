// cordova/core/internal/socket/socket.go

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
	"cordova/core/internal/config"
	"cordova/core/internal/store"
	"cordova/core/internal/vault"
	"cordova/core/ipc"
)

const version = "0.4.0"

// activeListener pairs a socket entry with its running net.Listener.
type activeListener struct {
	entry    config.SocketEntry
	listener net.Listener
}

// Server listens on one or more Unix domain sockets and dispatches IPC
// commands from authenticated cordova-admin clients.
type Server struct {
	socketsConfigPath string
	socketsConfig     *config.SocketsConfig
	secretsStore      *store.SecretsStore
	userStore         *store.UserStore
	secretsVault      *vault.SecretsVault
	usersVault        *vault.UsersVault
	auditLog          *audit.Logger
	secretsPassphrase []byte
	usersPassphrase   []byte
	writeMu           sync.Mutex
	listenMu          sync.Mutex
	auth              *auth.Authenticator
	sealCh            chan struct{}
	listeners         []activeListener
	ephemeralListener *activeListener
	ephemeralUsername string
	ephemeralToken    string
}

// NewServer creates a Server. Listeners are started by calling Start.
func NewServer(
	socketsConfigPath string,
	socketsConfig *config.SocketsConfig,
	secretsStore *store.SecretsStore,
	userStore *store.UserStore,
	secretsVault *vault.SecretsVault,
	usersVault *vault.UsersVault,
	auditLog *audit.Logger,
	secretsPassphrase, usersPassphrase []byte,
) *Server {
	srv := &Server{
		socketsConfigPath: socketsConfigPath,
		socketsConfig:     socketsConfig,
		secretsStore:      secretsStore,
		userStore:         userStore,
		secretsVault:      secretsVault,
		usersVault:        usersVault,
		auditLog:          auditLog,
		secretsPassphrase: secretsPassphrase,
		usersPassphrase:   usersPassphrase,
		sealCh:            make(chan struct{}, 1),
	}
	srv.auth = auth.New(userStore, &srv.writeMu, srv.persist, auditLog)
	return srv
}

// Start opens one listener per entry in socketsConfig.
func (s *Server) Start() error {
	for _, entry := range s.socketsConfig.Sockets {
		if err := s.startListener(entry); err != nil {
			s.Stop()
			return err
		}
	}
	return nil
}

// AddEphemeralSocket opens a temporary socket with the given entry. Used by
// --gen-root to create a short-lived unrestricted socket.
func (s *Server) AddEphemeralSocket(entry config.SocketEntry, username, tokenName string) error {
	ln, err := openSocket(entry.Path)
	if err != nil {
		return err
	}
	al := &activeListener{entry: entry, listener: ln}
	s.listenMu.Lock()
	s.ephemeralListener = al
	s.ephemeralUsername = username
	s.ephemeralToken = tokenName
	s.listenMu.Unlock()

	s.auditLog.Log(audit.Entry{Event: audit.EventSocketStart, Source: entry.Path})
	slog.Info("ephemeral socket started", "path", entry.Path)
	go s.acceptLoop(al)
	return nil
}

// SealRequested returns a channel that is written to when a seal command is
// received.
func (s *Server) SealRequested() <-chan struct{} {
	return s.sealCh
}

// Stop closes all listeners, removes socket files, and zeros passphrases.
func (s *Server) Stop() {
	s.listenMu.Lock()
	listeners := make([]activeListener, len(s.listeners))
	copy(listeners, s.listeners)
	ephemeral := s.ephemeralListener
	s.listeners = nil
	s.ephemeralListener = nil
	s.listenMu.Unlock()

	for _, al := range listeners {
		_ = al.listener.Close()
		_ = os.Remove(al.entry.Path)
		s.auditLog.Log(audit.Entry{Event: audit.EventSocketStop, Source: al.entry.Path})
	}
	if ephemeral != nil {
		_ = ephemeral.listener.Close()
		_ = os.Remove(ephemeral.entry.Path)
		s.auditLog.Log(audit.Entry{Event: audit.EventSocketStop, Source: ephemeral.entry.Path})

		// Remove the ephemeral token from the user store.
		if s.ephemeralUsername != "" && s.ephemeralToken != "" {
			s.writeMu.Lock()
			if err := s.userStore.RevokeToken(s.ephemeralUsername, s.ephemeralToken); err != nil {
				slog.Warn("revoking ephemeral token on stop", "err", err)
			}
			s.writeMu.Unlock()
		}
	}

	zeroBytes(s.secretsPassphrase)
	zeroBytes(s.usersPassphrase)
}

// startListener opens a socket at entry.Path and launches an accept loop.
func (s *Server) startListener(entry config.SocketEntry) error {
	ln, err := openSocket(entry.Path)
	if err != nil {
		return err
	}
	al := activeListener{entry: entry, listener: ln}
	s.listenMu.Lock()
	s.listeners = append(s.listeners, al)
	s.listenMu.Unlock()

	s.auditLog.Log(audit.Entry{Event: audit.EventSocketStart, Source: entry.Path})
	slog.Info("socket started", "name", entry.Name, "path", entry.Path)
	go s.acceptLoop(&al)
	return nil
}

// openSocket removes any stale file, opens a Unix socket, and sets permissions.
func openSocket(path string) (net.Listener, error) {
	_ = os.Remove(path)
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, fmt.Errorf("listening on %s: %w", path, err)
	}
	if err := os.Chmod(path, 0600); err != nil {
		_ = ln.Close()
		return nil, fmt.Errorf("setting socket permissions on %s: %w", path, err)
	}
	return ln, nil
}

func (s *Server) acceptLoop(al *activeListener) {
	for {
		conn, err := al.listener.Accept()
		if err != nil {
			return
		}
		go s.handleConn(conn, al.entry)
	}
}

func (s *Server) handleConn(conn net.Conn, entry config.SocketEntry) {
	defer func() { _ = conn.Close() }()

	if err := conn.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
		slog.Warn("SetDeadline failed", "path", entry.Path, "err", err)
		return
	}

	var req ipc.Request
	if err := json.NewDecoder(conn).Decode(&req); err != nil {
		writeResp(conn, ipc.Response{OK: false, Error: "invalid request"})
		return
	}

	result := s.auth.Authenticate(req.Username, req.Token, entry.Path, req.Command, entry.Scope)
	if !result.Allowed {
		writeResp(conn, ipc.Response{OK: false, Error: result.Err})
		return
	}

	// TouchToken is called outside writeMu; it uses store.mu internally.
	// LastUsed updates are best-effort — occasional loss under concurrent seal
	// is acceptable.
	s.userStore.TouchToken(result.User.Name, result.Token.Name)

	writeResp(conn, s.dispatch(req, result.User))
}

func (s *Server) dispatch(req ipc.Request, user *vault.User) ipc.Response {
	adminOnly := map[string]bool{
		ipc.CmdTokenAdd:       true,
		ipc.CmdTokenRevoke:    true,
		ipc.CmdTokenRevokeAll: true,
		ipc.CmdTokenList:      true,
		ipc.CmdUserAdd:        true,
		ipc.CmdUserList:       true,
		ipc.CmdUserGet:        true,
		ipc.CmdUserDelete:     true,
		ipc.CmdSocketAdd:      true,
		ipc.CmdSocketList:     true,
		ipc.CmdSocketDelete:   true,
		ipc.CmdSeal:           true,
	}
	if adminOnly[req.Command] && !user.Admin {
		return errResp("admin access required")
	}

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
		return s.handleTokenRevokeAll(req.Params)
	case ipc.CmdUserAdd:
		return s.handleUserAdd(req.Params)
	case ipc.CmdUserList:
		return s.handleUserList()
	case ipc.CmdUserGet:
		return s.handleUserGet(req.Params)
	case ipc.CmdUserDelete:
		return s.handleUserDelete(req.Params)
	case ipc.CmdSocketAdd:
		return s.handleSocketAdd(req.Params)
	case ipc.CmdSocketList:
		return s.handleSocketList()
	case ipc.CmdSocketDelete:
		return s.handleSocketDelete(req.Params)
	case ipc.CmdSeal:
		return s.handleSeal()
	case ipc.CmdStatus:
		return s.handleStatus()
	default:
		return errResp("unknown command: " + req.Command)
	}
}

// ── Key handlers ──────────────────────────────────────────────────────────────

func (s *Server) handleKeyGet(raw json.RawMessage) ipc.Response {
	var p ipc.KeyGetParams
	if err := json.Unmarshal(raw, &p); err != nil {
		return errResp("invalid params: " + err.Error())
	}
	value, err := s.secretsStore.GetKey(p.Name)
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

	_, getErr := s.secretsStore.GetKey(p.Name)
	isRotate := getErr == nil

	if err := s.secretsStore.SetKey(p.Name, p.Value); err != nil {
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

	if err := s.secretsStore.DeleteKey(p.Name); err != nil {
		return errResp(err.Error())
	}
	if err := s.persist(); err != nil {
		return errResp("persist failed: " + err.Error())
	}
	s.auditLog.Log(audit.Entry{Event: audit.EventKeyDeleted, Key: p.Name})
	return okResp(ipc.AckData{Message: "ok"})
}

// handleKeyList returns the names of all keys. Read-only.
func (s *Server) handleKeyList() ipc.Response {
	keys, err := s.secretsStore.ListKeys()
	if err != nil {
		return errResp(err.Error())
	}
	if keys == nil {
		keys = []string{}
	}
	return okResp(ipc.KeyListData{Keys: keys})
}

// ── Token handlers ────────────────────────────────────────────────────────────

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

	secret, err := s.userStore.AddToken(p.Username, p.Name, p.Description, expiresAt)
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
			"user":        p.Username,
			"name":        p.Name,
			"description": p.Description,
			"expires_at":  p.ExpiresAt,
		},
	})
	return okResp(ipc.TokenAddData{
		Username:    p.Username,
		Name:        p.Name,
		Secret:      secret,
		Description: p.Description,
		ExpiresAt:   p.ExpiresAt,
	})
}

// handleTokenList returns all tokens across all users. Read-only.
func (s *Server) handleTokenList() ipc.Response {
	pairs, err := s.userStore.ListAllTokens()
	if err != nil {
		return errResp(err.Error())
	}
	summaries := make([]ipc.TokenSummary, 0, len(pairs))
	for _, p := range pairs {
		t := p.Token
		ts := ipc.TokenSummary{
			Username:    p.Username,
			Name:        t.Name,
			Description: t.Description,
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
		summaries = append(summaries, ts)
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

	if err := s.userStore.RevokeToken(p.Username, p.Name); err != nil {
		return errResp(err.Error())
	}
	if err := s.persist(); err != nil {
		return errResp("persist failed: " + err.Error())
	}
	s.auditLog.Log(audit.Entry{
		Event: audit.EventTokenRevoked,
		Extra: map[string]string{"user": p.Username, "name": p.Name},
	})
	return okResp(ipc.AckData{Message: "ok"})
}

func (s *Server) handleTokenRevokeAll(raw json.RawMessage) ipc.Response {
	var p ipc.TokenRevokeAllParams
	if raw != nil {
		_ = json.Unmarshal(raw, &p)
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	if err := s.userStore.RevokeAllTokens(p.Username); err != nil {
		return errResp(err.Error())
	}
	if err := s.persist(); err != nil {
		return errResp("persist failed: " + err.Error())
	}
	s.auditLog.Log(audit.Entry{
		Event: audit.EventTokenRevokeAll,
		Extra: map[string]string{"user": p.Username},
	})
	return okResp(ipc.AckData{Message: "all tokens revoked"})
}

// ── User handlers ─────────────────────────────────────────────────────────────

func (s *Server) handleUserAdd(raw json.RawMessage) ipc.Response {
	var p ipc.UserAddParams
	if err := json.Unmarshal(raw, &p); err != nil {
		return errResp("invalid params: " + err.Error())
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	if err := s.userStore.AddUser(p.Name, p.Parent, p.Admin, p.Namespaces, p.Keys, p.Sockets, p.Writable); err != nil {
		return errResp(err.Error())
	}
	if err := s.persist(); err != nil {
		return errResp("persist failed: " + err.Error())
	}
	s.auditLog.Log(audit.Entry{
		Event: "user_added",
		Extra: map[string]string{"name": p.Name, "parent": p.Parent},
	})
	return okResp(ipc.AckData{Message: "user created: " + p.Name})
}

// handleUserList returns all users. Read-only.
func (s *Server) handleUserList() ipc.Response {
	users, err := s.userStore.ListUsers()
	if err != nil {
		return errResp(err.Error())
	}
	summaries := make([]ipc.UserSummary, 0, len(users))
	for _, u := range users {
		summaries = append(summaries, ipc.UserSummary{
			Name:       u.Name,
			Parent:     u.Parent,
			Admin:      u.Admin,
			Namespaces: u.Namespaces,
			Keys:       u.Keys,
			Sockets:    u.Sockets,
			Writable:   u.Writable,
			TokenCount: len(u.Tokens),
			CreatedAt:  u.CreatedAt.Format(time.RFC3339),
		})
	}
	return okResp(ipc.UserListData{Users: summaries})
}

// handleUserGet returns a single user. Read-only.
func (s *Server) handleUserGet(raw json.RawMessage) ipc.Response {
	var p ipc.UserGetParams
	if err := json.Unmarshal(raw, &p); err != nil {
		return errResp("invalid params: " + err.Error())
	}
	u, err := s.userStore.GetUser(p.Name)
	if err != nil {
		return errResp(err.Error())
	}
	return okResp(ipc.UserSummary{
		Name:       u.Name,
		Parent:     u.Parent,
		Admin:      u.Admin,
		Namespaces: u.Namespaces,
		Keys:       u.Keys,
		Sockets:    u.Sockets,
		Writable:   u.Writable,
		TokenCount: len(u.Tokens),
		CreatedAt:  u.CreatedAt.Format(time.RFC3339),
	})
}

func (s *Server) handleUserDelete(raw json.RawMessage) ipc.Response {
	var p ipc.UserDeleteParams
	if err := json.Unmarshal(raw, &p); err != nil {
		return errResp("invalid params: " + err.Error())
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	if err := s.userStore.DeleteUser(p.Name); err != nil {
		return errResp(err.Error())
	}
	if err := s.persist(); err != nil {
		return errResp("persist failed: " + err.Error())
	}
	s.auditLog.Log(audit.Entry{
		Event: "user_deleted",
		Extra: map[string]string{"name": p.Name},
	})
	return okResp(ipc.AckData{Message: "user deleted: " + p.Name})
}

// ── Socket handlers ───────────────────────────────────────────────────────────

// handleSocketList returns all configured sockets and whether they are live.
func (s *Server) handleSocketList() ipc.Response {
	s.listenMu.Lock()
	defer s.listenMu.Unlock()

	liveSet := make(map[string]bool)
	for _, al := range s.listeners {
		liveSet[al.entry.Name] = true
	}
	if s.ephemeralListener != nil {
		liveSet[s.ephemeralListener.entry.Name] = true
	}

	var summaries []ipc.SocketSummary
	for _, e := range s.socketsConfig.Sockets {
		summaries = append(summaries, ipc.SocketSummary{
			Name: e.Name,
			Path: e.Path,
			Scope: ipc.SocketScope{
				Unrestricted: e.Scope.Unrestricted,
				Namespaces:   e.Scope.Namespaces,
				Keys:         e.Scope.Keys,
				Writable:     e.Scope.Writable,
			},
			Live: liveSet[e.Name],
		})
	}
	if s.ephemeralListener != nil {
		e := s.ephemeralListener.entry
		summaries = append(summaries, ipc.SocketSummary{
			Name: e.Name,
			Path: e.Path,
			Scope: ipc.SocketScope{
				Unrestricted: e.Scope.Unrestricted,
			},
			Live: true,
		})
	}
	return okResp(ipc.SocketListData{Sockets: summaries})
}

func (s *Server) handleSocketAdd(raw json.RawMessage) ipc.Response {
	var p ipc.SocketAddParams
	if err := json.Unmarshal(raw, &p); err != nil {
		return errResp("invalid params: " + err.Error())
	}

	entry := config.SocketEntry{
		Name: p.Name,
		Path: p.Path,
		Scope: config.SocketScope{
			Unrestricted: p.Scope.Unrestricted,
			Namespaces:   p.Scope.Namespaces,
			Keys:         p.Scope.Keys,
			Writable:     p.Scope.Writable,
		},
	}

	s.listenMu.Lock()
	for _, e := range s.socketsConfig.Sockets {
		if e.Name == p.Name {
			s.listenMu.Unlock()
			return errResp(fmt.Sprintf("socket %q already exists", p.Name))
		}
	}
	s.listenMu.Unlock()

	if err := s.startListener(entry); err != nil {
		return errResp("starting listener: " + err.Error())
	}

	s.listenMu.Lock()
	s.socketsConfig.Sockets = append(s.socketsConfig.Sockets, entry)
	s.listenMu.Unlock()

	if s.socketsConfigPath != "" {
		if err := config.SaveSockets(s.socketsConfigPath, s.socketsConfig); err != nil {
			slog.Warn("saving sockets config after add", "err", err)
		}
	}
	s.auditLog.Log(audit.Entry{
		Event: "socket_added",
		Extra: map[string]string{"name": p.Name, "path": p.Path},
	})
	return okResp(ipc.AckData{Message: "socket added: " + p.Name})
}

func (s *Server) handleSocketDelete(raw json.RawMessage) ipc.Response {
	var p ipc.SocketDeleteParams
	if err := json.Unmarshal(raw, &p); err != nil {
		return errResp("invalid params: " + err.Error())
	}

	s.listenMu.Lock()
	idx := -1
	for i, al := range s.listeners {
		if al.entry.Name == p.Name {
			idx = i
			break
		}
	}
	if idx < 0 {
		s.listenMu.Unlock()
		return errResp(fmt.Sprintf("socket %q not found or not currently active", p.Name))
	}
	al := s.listeners[idx]
	s.listeners = append(s.listeners[:idx], s.listeners[idx+1:]...)
	s.listenMu.Unlock()

	_ = al.listener.Close()
	_ = os.Remove(al.entry.Path)
	s.auditLog.Log(audit.Entry{Event: audit.EventSocketStop, Source: al.entry.Path})

	// Remove from in-memory config.
	s.listenMu.Lock()
	newSockets := s.socketsConfig.Sockets[:0]
	for _, e := range s.socketsConfig.Sockets {
		if e.Name != p.Name {
			newSockets = append(newSockets, e)
		}
	}
	s.socketsConfig.Sockets = newSockets
	s.listenMu.Unlock()

	if s.socketsConfigPath != "" {
		if err := config.SaveSockets(s.socketsConfigPath, s.socketsConfig); err != nil {
			slog.Warn("saving sockets config after delete", "err", err)
		}
	}
	return okResp(ipc.AckData{Message: "socket deleted: " + p.Name})
}

// ── Admin handlers ────────────────────────────────────────────────────────────

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
		Sealed:  s.secretsStore.IsSealed(),
		Version: version,
	})
}

// ── Persistence ───────────────────────────────────────────────────────────────

// persist seals both vaults. Must be called with writeMu held.
func (s *Server) persist() error {
	secSnap, err := s.secretsStore.Snapshot()
	if err != nil {
		return fmt.Errorf("snapshotting secrets: %w", err)
	}
	if err := s.secretsVault.Seal(secSnap, s.secretsPassphrase); err != nil {
		return fmt.Errorf("sealing secrets: %w", err)
	}

	usersSnap, err := s.userStore.Snapshot()
	if err != nil {
		return fmt.Errorf("snapshotting users: %w", err)
	}
	if err := s.usersVault.Seal(usersSnap, s.usersPassphrase); err != nil {
		return fmt.Errorf("sealing users: %w", err)
	}
	return nil
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func okResp(data any) ipc.Response {
	b, _ := json.Marshal(data)
	return ipc.Response{OK: true, Data: json.RawMessage(b)}
}

func errResp(msg string) ipc.Response {
	return ipc.Response{OK: false, Error: msg}
}

func writeResp(conn net.Conn, resp ipc.Response) {
	_ = json.NewEncoder(conn).Encode(resp)
}

func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}