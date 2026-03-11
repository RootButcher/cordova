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
	CmdSeal           = "seal"
	CmdStatus         = "status"
)

type Request struct {
	Token   string          `json:"token"`
	Command string          `json:"command"`
	Params  json.RawMessage `json:"params,omitempty"`
}
type Response struct {
	OK    bool            `json:"ok"`
	Data  json.RawMessage `json:"data,omitempty"`
	Error string          `json:"error,omitempty"`
}

// ── Param structs ─────────────────────────────────────────────────────────────

type KeyGetParams struct {
	Name string `json:"name"`
}
type KeySetParams struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}
type KeyDeleteParams struct {
	Name string `json:"name"`
}
type TokenAddParams struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Role        string   `json:"role"`
	ExpiresAt   string   `json:"expires_at,omitempty"`
	CIDRs       []string `json:"cidrs,omitempty"`
	Namespaces  []string `json:"namespaces,omitempty"`
	Keys        []string `json:"keys,omitempty"`
	Writable    bool     `json:"writable,omitempty"`
}
type TokenRevokeParams struct {
	Name string `json:"name"`
}

// ── Data structs ──────────────────────────────────────────────────────────────

type KeyGetData struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}
type AckData struct {
	Message string `json:"message"`
}

type KeyListData struct {
	Keys []string `json:"keys"`
}

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

type TokenListData struct {
	Tokens []TokenSummary `json:"tokens"`
}

type StatusData struct {
	Sealed  bool   `json:"sealed"`
	Version string `json:"version"`
}
