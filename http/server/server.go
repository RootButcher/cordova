// cordova/http/server/server.go

package server

import (
	"encoding/json"
	"net/http"
	"strings"

	"cordova/core/client"
	"cordova/core/ipc"
)

// Config holds the server configuration.
type Config struct {
	SocketPath string
	ListenAddr string
	TLSCert    string
	TLSKey     string
}

// Handler returns an http.Handler wired to the given socket path.
func Handler(socketPath string) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/keys", func(w http.ResponseWriter, r *http.Request) {
		handleKeyList(w, r, socketPath)
	})
	mux.HandleFunc("/key/", func(w http.ResponseWriter, r *http.Request) {
		handleKey(w, r, socketPath)
	})
	mux.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		handleStatus(w, r, socketPath)
	})
	return mux
}

// Run starts the HTTP(S) server.
func Run(cfg Config) error {
	h := Handler(cfg.SocketPath)
	if cfg.TLSCert != "" && cfg.TLSKey != "" {
		return http.ListenAndServeTLS(cfg.ListenAddr, cfg.TLSCert, cfg.TLSKey, h)
	}
	return http.ListenAndServe(cfg.ListenAddr, h)
}

// writeJSON writes a JSON response with the given status code.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// writeError writes a JSON error response.
func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// authClient extracts Basic Auth credentials and returns a client, or writes
// a 401 and returns nil.
func authClient(w http.ResponseWriter, r *http.Request, socketPath string) *client.Client {
	username, token, ok := r.BasicAuth()
	if !ok || username == "" || token == "" {
		w.Header().Set("WWW-Authenticate", `Basic realm="cordova"`)
		writeError(w, http.StatusUnauthorized, "authentication required")
		return nil
	}
	return client.New(socketPath, username, token)
}

// ipcStatus maps an IPC error string to an HTTP status code.
func ipcStatus(errMsg string) int {
	lower := strings.ToLower(errMsg)
	switch {
	case strings.Contains(lower, "not found"):
		return http.StatusNotFound
	case strings.Contains(lower, "denied"), strings.Contains(lower, "unauthorized"),
		strings.Contains(lower, "forbidden"), strings.Contains(lower, "permission"):
		return http.StatusForbidden
	default:
		return http.StatusInternalServerError
	}
}

// handleKeyList handles GET /keys.
func handleKeyList(w http.ResponseWriter, r *http.Request, socketPath string) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	c := authClient(w, r, socketPath)
	if c == nil {
		return
	}
	resp, err := c.Send(ipc.CmdKeyList, nil)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !resp.OK {
		writeError(w, ipcStatus(resp.Error), resp.Error)
		return
	}
	var data ipc.KeyListData
	if err := json.Unmarshal(resp.Data, &data); err != nil {
		writeError(w, http.StatusInternalServerError, "malformed daemon response")
		return
	}
	writeJSON(w, http.StatusOK, data)
}

// handleKey routes /key/{name} to GET, PUT, or DELETE handlers.
func handleKey(w http.ResponseWriter, r *http.Request, socketPath string) {
	name := strings.TrimPrefix(r.URL.Path, "/key/")
	if name == "" {
		writeError(w, http.StatusBadRequest, "key name required")
		return
	}
	switch r.Method {
	case http.MethodGet:
		handleKeyGet(w, r, socketPath, name)
	case http.MethodPut:
		handleKeySet(w, r, socketPath, name)
	case http.MethodDelete:
		handleKeyDelete(w, r, socketPath, name)
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func handleKeyGet(w http.ResponseWriter, r *http.Request, socketPath, name string) {
	c := authClient(w, r, socketPath)
	if c == nil {
		return
	}
	resp, err := c.Send(ipc.CmdKeyGet, ipc.KeyGetParams{Name: name})
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !resp.OK {
		writeError(w, ipcStatus(resp.Error), resp.Error)
		return
	}
	var data ipc.KeyGetData
	if err := json.Unmarshal(resp.Data, &data); err != nil {
		writeError(w, http.StatusInternalServerError, "malformed daemon response")
		return
	}
	writeJSON(w, http.StatusOK, data)
}

func handleKeySet(w http.ResponseWriter, r *http.Request, socketPath, name string) {
	c := authClient(w, r, socketPath)
	if c == nil {
		return
	}
	var body struct {
		Value string `json:"value"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	resp, err := c.Send(ipc.CmdKeySet, ipc.KeySetParams{Name: name, Value: body.Value})
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !resp.OK {
		writeError(w, ipcStatus(resp.Error), resp.Error)
		return
	}
	var data ipc.AckData
	if err := json.Unmarshal(resp.Data, &data); err != nil {
		writeError(w, http.StatusInternalServerError, "malformed daemon response")
		return
	}
	writeJSON(w, http.StatusOK, data)
}

func handleKeyDelete(w http.ResponseWriter, r *http.Request, socketPath, name string) {
	c := authClient(w, r, socketPath)
	if c == nil {
		return
	}
	resp, err := c.Send(ipc.CmdKeyDelete, ipc.KeyDeleteParams{Name: name})
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !resp.OK {
		writeError(w, ipcStatus(resp.Error), resp.Error)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func handleStatus(w http.ResponseWriter, r *http.Request, socketPath string) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	c := authClient(w, r, socketPath)
	if c == nil {
		return
	}
	resp, err := c.Send(ipc.CmdStatus, nil)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !resp.OK {
		writeError(w, ipcStatus(resp.Error), resp.Error)
		return
	}
	var data ipc.StatusData
	if err := json.Unmarshal(resp.Data, &data); err != nil {
		writeError(w, http.StatusInternalServerError, "malformed daemon response")
		return
	}
	writeJSON(w, http.StatusOK, data)
}
