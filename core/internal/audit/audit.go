// cordova/core/internal/audit/audit.go

package audit

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"
)

const (
	EventVaultUnseal    = "vault_unseal"
	EventVaultSeal      = "vault_seal"
	EventKeyAdded       = "key_added"
	EventKeyRotated     = "key_rotated"
	EventKeyDeleted     = "key_deleted"
	EventKeyGet         = "key_get"
	EventTokenAdded     = "token_added"
	EventTokenRevoked   = "token_revoked"
	EventTokenRevokeAll = "token_revoke_all"
	EventSealRequest    = "seal_request"
	EventAuthOK         = "auth_ok"
	EventAuthDenied     = "auth_denied"
	EventTokenExpired   = "token_expired"
	EventSocketStart    = "socket_start"
	EventSocketStop     = "socket_stop"
)

type Entry struct {
	Time    time.Time         `json:"time"`
	Event   string            `json:"event"`
	Result  string            `json:"result,omitempty"`
	Reason  string            `json:"reason,omitempty"`
	TokenID string            `json:"token_id,omitempty"`
	Source  string            `json:"source,omitempty"`
	Key     string            `json:"key,omitempty"`
	Extra   map[string]string `json:"extra,omitempty"`
}

type Logger struct {
	mu   sync.Mutex
	f    *os.File
	slog *slog.Logger
}

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

func (l *Logger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.f.Close()
}
