// cordova/core/ipc/protocol.go

package ipc

import "encoding/json"

const (
	CmdKeyGet         = "key.get"
	CmdKeySet         = "key.set"
	CmdKeyDelete      = "key.delete"
	CmdKeyList        = "key.list"
	CmdTokenAdd       = "token.add"
	CmdTokenList      = "token.list"
	CmdTokenRevoke    = "token.revoke"
	CmdTokenRevokeAll = "token.revoke-all"
	CmdUserAdd        = "user.add"
	CmdUserList       = "user.list"
	CmdUserGet        = "user.get"
	CmdUserDelete     = "user.delete"
	CmdSocketList     = "socket.list"
	CmdSocketAdd      = "socket.add"
	CmdSocketDelete   = "socket.delete"
	CmdSeal           = "seal"
	CmdStatus         = "status"
)

// Request is the wire format for every IPC command sent by a client.
type Request struct {
	Username string          `json:"username"`
	Token    string          `json:"token"`
	Command  string          `json:"command"`
	Params   json.RawMessage `json:"params,omitempty"`
}

// Response is the wire format for every IPC reply sent by the daemon.
type Response struct {
	OK    bool            `json:"ok"`
	Data  json.RawMessage `json:"data,omitempty"`
	Error string          `json:"error,omitempty"`
}

// ── Key param / data structs ──────────────────────────────────────────────────

// KeyGetParams carries the key name for a key.get request.
type KeyGetParams struct {
	Name string `json:"name"`
}

// KeySetParams carries the name and value for a key.set request.
type KeySetParams struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// KeyDeleteParams carries the key name for a key.delete request.
type KeyDeleteParams struct {
	Name string `json:"name"`
}

// KeyGetData is the response body for a key.get request.
type KeyGetData struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// KeyListData is the response body for a key.list request.
type KeyListData struct {
	Keys []string `json:"keys"`
}

// ── Token param / data structs ────────────────────────────────────────────────

// TokenAddParams carries fields for a token.add request.
// ExpiresAt wire format: "" = persistent, "ephemeral" = process-scoped,
// RFC3339 timestamp = TTL.
type TokenAddParams struct {
	Username    string `json:"username"`
	Name        string `json:"name"`
	Description string `json:"description"`
	ExpiresAt   string `json:"expires_at,omitempty"`
}

// TokenRevokeParams carries fields for a token.revoke request.
type TokenRevokeParams struct {
	Username string `json:"username"`
	Name     string `json:"name"`
}

// TokenRevokeAllParams carries an optional username for token.revoke-all.
// An empty Username means all tokens for all users are revoked.
type TokenRevokeAllParams struct {
	Username string `json:"username,omitempty"`
}

// TokenAddData is the response body for a successful token.add.
type TokenAddData struct {
	Username    string `json:"username"`
	Name        string `json:"name"`
	Secret      string `json:"secret"`
	Description string `json:"description"`
	ExpiresAt   string `json:"expires_at,omitempty"`
}

// TokenSummary is one entry in a token.list response.
type TokenSummary struct {
	Username    string `json:"username"`
	Name        string `json:"name"`
	Description string `json:"description"`
	ExpiresAt   string `json:"expires_at,omitempty"`
	CreatedAt   string `json:"created_at"`
	LastUsed    string `json:"last_used,omitempty"`
}

// TokenListData is the response body for a token.list request.
type TokenListData struct {
	Tokens []TokenSummary `json:"tokens"`
}

// ── User param / data structs ─────────────────────────────────────────────────

// UserAddParams carries fields for a user.add request.
type UserAddParams struct {
	Name       string   `json:"name"`
	Parent     string   `json:"parent"`
	Admin      bool     `json:"admin"`
	Namespaces []string `json:"namespaces,omitempty"`
	Keys       []string `json:"keys,omitempty"`
	Sockets    []string `json:"sockets,omitempty"`
	Writable   bool     `json:"writable,omitempty"`
}

// UserDeleteParams carries the username for a user.delete request.
type UserDeleteParams struct {
	Name string `json:"name"`
}

// UserGetParams carries the username for a user.get request.
type UserGetParams struct {
	Name string `json:"name"`
}

// UserSummary is one entry in a user.list response.
type UserSummary struct {
	Name       string   `json:"name"`
	Parent     string   `json:"parent"`
	Admin      bool     `json:"admin"`
	Namespaces []string `json:"namespaces,omitempty"`
	Keys       []string `json:"keys,omitempty"`
	Sockets    []string `json:"sockets,omitempty"`
	Writable   bool     `json:"writable,omitempty"`
	TokenCount int      `json:"token_count"`
	CreatedAt  string   `json:"created_at"`
}

// UserListData is the response body for a user.list request.
type UserListData struct {
	Users []UserSummary `json:"users"`
}

// ── Socket param / data structs ───────────────────────────────────────────────

// SocketScope mirrors config.SocketScope for use in IPC messages.
type SocketScope struct {
	Unrestricted bool     `json:"unrestricted,omitempty"`
	Namespaces   []string `json:"namespaces,omitempty"`
	Keys         []string `json:"keys,omitempty"`
	Writable     bool     `json:"writable,omitempty"`
}

// SocketAddParams carries fields for a socket.add request.
type SocketAddParams struct {
	Name  string      `json:"name"`
	Path  string      `json:"path"`
	Scope SocketScope `json:"scope"`
}

// SocketDeleteParams carries the socket name for a socket.delete request.
type SocketDeleteParams struct {
	Name string `json:"name"`
}

// SocketSummary is one entry in a socket.list response.
type SocketSummary struct {
	Name  string      `json:"name"`
	Path  string      `json:"path"`
	Scope SocketScope `json:"scope"`
	Live  bool        `json:"live"`
}

// SocketListData is the response body for a socket.list request.
type SocketListData struct {
	Sockets []SocketSummary `json:"sockets"`
}

// ── Generic ───────────────────────────────────────────────────────────────────

// AckData is a simple acknowledgement response body.
type AckData struct {
	Message string `json:"message"`
}

// StatusData is the response body for a status request.
type StatusData struct {
	Sealed  bool   `json:"sealed"`
	Version string `json:"version"`
}