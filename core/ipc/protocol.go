// cordova/core/ipc/protocol.go
//
// Package ipc defines the shared wire types used by both cordova-vault and
// cordova-admin. All communication is newline-delimited JSON over a Unix
// domain socket. Neither side should import the other's packages; this package
// is the shared contract between them.

package ipc

import "encoding/json"

// Command constants identify the operation requested in a Request.
const (
	CmdKeyGet         = "key.get"          // retrieve a key value
	CmdKeySet         = "key.set"          // add or rotate a key
	CmdKeyDelete      = "key.delete"       // delete a key
	CmdKeyList        = "key.list"         // list all key names
	CmdTokenAdd       = "token.add"        // create a new token
	CmdTokenList      = "token.list"       // list all tokens
	CmdTokenRevoke    = "token.revoke"     // revoke a token by name
	CmdTokenRevokeAll = "token.revoke-all" // revoke every token
	CmdSeal           = "seal"             // seal the vault and stop the daemon
	CmdStatus         = "status"           // query daemon status
)

// Request is sent from cordova-admin to cordova-vault over the Unix socket.
type Request struct {
	// Token is the bearer credential — either the ephemeral root token or a
	// persistent admin token — used to authenticate the request.
	Token string `json:"token"`

	// Command identifies the operation to perform (use the Cmd* constants).
	Command string `json:"command"`

	// Params holds command-specific arguments, encoded as JSON. It may be
	// omitted for commands that take no arguments (e.g. key.list, status).
	Params json.RawMessage `json:"params,omitempty"`
}

// Response is sent from cordova-vault back to cordova-admin.
type Response struct {
	// OK is true when the command succeeded, false on any error.
	OK bool `json:"ok"`

	// Data holds the command-specific result payload, encoded as JSON.
	// It is present only when OK is true.
	Data json.RawMessage `json:"data,omitempty"`

	// Error is a human-readable error message. Present only when OK is false.
	Error string `json:"error,omitempty"`
}

// ── Param structs ─────────────────────────────────────────────────────────────

// KeyGetParams identifies the key to retrieve by its full "namespace/name".
type KeyGetParams struct {
	Name string `json:"name"`
}

// KeySetParams is used for both key.add and key.rotate. The daemon decides
// which audit event to emit based on whether the key already exists.
type KeySetParams struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// KeyDeleteParams identifies the key to remove by its full "namespace/name".
type KeyDeleteParams struct {
	Name string `json:"name"`
}

// TokenAddParams carries the fields required to create a new token.
type TokenAddParams struct {
	// Name is the unique slug identifier for the token, e.g. "ops-box".
	// Used for display and revocation. Must be lowercase letters, digits,
	// and hyphens only.
	Name string `json:"name"`

	// Description is a human-readable label for the token.
	Description string `json:"description"`

	// Role is the token's access level: "admin" or "access".
	// Admin tokens have full vault access. Access tokens are scoped
	// (for future cordova-http / cordova-ssh consumers).
	Role string `json:"role"`

	// ExpiresAt controls the token lifetime. Three forms are accepted:
	//   ""           or omitted → persistent (no expiry, stored to disk)
	//   "ephemeral"             → process-scoped (never stored to disk)
	//   RFC3339 timestamp       → TTL (stored, rejected and deleted after expiry)
	ExpiresAt string `json:"expires_at,omitempty"`

	// The following fields are only meaningful for Role == "access".

	// CIDRs restricts which source IPs may use this token.
	CIDRs []string `json:"cidrs,omitempty"`

	// Namespaces allows access to all keys under the given namespace prefixes.
	Namespaces []string `json:"namespaces,omitempty"`

	// Keys lists explicit key names this token may access.
	Keys []string `json:"keys,omitempty"`

	// Writable permits the token to write key values as well as read them.
	Writable bool `json:"writable,omitempty"`
}

// TokenRevokeParams identifies the token to revoke by name.
type TokenRevokeParams struct {
	Name string `json:"name"`
}

// ── Data structs ──────────────────────────────────────────────────────────────

// KeyGetData is returned by key.get and contains the plaintext key value.
// This is only transmitted over the local Unix socket, never over a network.
type KeyGetData struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// AckData is the generic success payload for mutating commands that do not
// need to return specific data (e.g. key.delete, key.set, token.revoke).
type AckData struct {
	Message string `json:"message"`
}

// KeyListData holds the names (not values) of all keys currently in the vault.
type KeyListData struct {
	Keys []string `json:"keys"`
}

// TokenAddData is returned after a successful token.add. Secret is the
// raw bearer credential — shown to the operator once and never stored again.
type TokenAddData struct {
	Name        string   `json:"name"`
	Secret      string   `json:"secret"`
	Description string   `json:"description"`
	Role        string   `json:"role"`
	ExpiresAt   string   `json:"expires_at,omitempty"`
	CIDRs       []string `json:"cidrs,omitempty"`
	Namespaces  []string `json:"namespaces,omitempty"`
	Keys        []string `json:"keys,omitempty"`
	Writable    bool     `json:"writable,omitempty"`
}

// TokenSummary is a safe, displayable view of a vault.Token. ExpiresAt is
// "persistent", "ephemeral", or an RFC3339 timestamp. LastUsed is RFC3339 or
// empty if never used. The secret is never included.
type TokenSummary struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Role        string   `json:"role"`
	ExpiresAt   string   `json:"expires_at,omitempty"`
	CIDRs       []string `json:"cidrs,omitempty"`
	Namespaces  []string `json:"namespaces,omitempty"`
	Keys        []string `json:"keys,omitempty"`
	Writable    bool     `json:"writable,omitempty"`
	CreatedAt   string   `json:"created_at"`
	LastUsed    string   `json:"last_used,omitempty"`
}

// TokenListData holds the full list of tokens for a token.list response.
type TokenListData struct {
	Tokens []TokenSummary `json:"tokens"`
}

// StatusData reports whether the vault is currently sealed and the daemon version.
type StatusData struct {
	Sealed  bool   `json:"sealed"`
	Version string `json:"version"`
}
