// cordova/core/internal/audit/audit.go
//
// Package audit provides structured JSON audit logging. Every security-relevant
// event is written to a log file and mirrored to stdout for systemd journal
// capture. Key material must never appear in any log entry.

package audit

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"
)

// Event type constants. Each constant is a stable string used as the "event"
// field in every audit log entry. Do not rename — external tooling or SIEMs
// may parse these values.
const (
	EventVaultUnseal    = "vault_unseal"     // vault successfully decrypted
	EventVaultSeal      = "vault_seal"       // vault sealed and daemon exiting
	EventKeyAdded       = "key_added"        // new key created
	EventKeyRotated     = "key_rotated"      // existing key value replaced
	EventKeyDeleted     = "key_deleted"      // key removed from vault
	EventKeyGet         = "key_get"          // key value retrieved
	EventTokenAdded     = "token_added"      // new token created
	EventTokenRevoked   = "token_revoked"    // single token removed
	EventTokenRevokeAll = "token_revoke_all" // all tokens removed
	EventSealRequest    = "seal_request"     // seal command received over socket
	EventAuthOK         = "auth_ok"          // token accepted; command about to be dispatched
	EventAuthDenied     = "auth_denied"      // token rejected by the socket server
	EventTokenExpired   = "token_expired"    // expired TTL token used; token deleted from store
	EventSocketStart    = "socket_start"     // Unix socket listener started
	EventSocketStop     = "socket_stop"      // Unix socket listener stopped
)

// Entry is a single structured audit log record. No secret values or key
// material should ever appear in any field.
type Entry struct {
	// Time is set automatically to UTC now when Log is called.
	Time time.Time `json:"time"`

	// Event identifies what happened (use the Event* constants above).
	Event string `json:"event"`

	// Result is an optional outcome qualifier, e.g. "ok" or "denied".
	Result string `json:"result,omitempty"`

	// Reason is a human-readable explanation for failures or denials.
	Reason string `json:"reason,omitempty"`

	// TokenID is the ID prefix of the token involved, if any.
	TokenID string `json:"token_id,omitempty"`

	// Source is the socket path or remote IP, depending on the event context.
	Source string `json:"source,omitempty"`

	// Key is the "namespace/name" of the key involved in key events.
	// Never include the key's value here.
	Key string `json:"key,omitempty"`

	// Extra holds any additional context fields that don't fit the above.
	Extra map[string]string `json:"extra,omitempty"`
}

// Logger writes structured JSON audit entries to a file and to stdout so that
// systemd journal can capture them. All methods are safe for concurrent use.
type Logger struct {
	mu   sync.Mutex
	f    *os.File
	slog *slog.Logger
}

// New opens (or creates) the audit log file at path with mode 0600.
func New(path string) (*Logger, error) {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return nil, fmt.Errorf("opening audit log at %s: %w", path, err)
	}

	sl := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	return &Logger{f: f, slog: sl}, nil
}

// Log writes an audit entry to both the log file and stdout. The timestamp is
// always set to UTC now, overwriting any value the caller may have set.
func (l *Logger) Log(e Entry) {
	e.Time = time.Now().UTC()

	b, err := json.Marshal(e)
	if err != nil {
		l.slog.Error("failed to marshal audit entry", "error", err)
		return
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	_, _ = l.f.Write(b)
	_, _ = l.f.Write([]byte("\n"))

	// Mirror to stdout so systemd journal captures it.
	// Only include non-empty fields to keep the output readable.
	args := []any{"event", e.Event}
	if e.Result != "" {
		args = append(args, "result", e.Result)
	}
	if e.TokenID != "" {
		args = append(args, "token_id", e.TokenID)
	}
	if e.Source != "" {
		args = append(args, "source", e.Source)
	}
	if e.Key != "" {
		args = append(args, "key", e.Key)
	}
	l.slog.Info("audit", args...)
}

// Close flushes and closes the underlying log file.
func (l *Logger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.f.Close()
}
