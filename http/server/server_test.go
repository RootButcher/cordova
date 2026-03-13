// cordova/http/server/server_test.go

package server_test

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"cordova/core/ipc"
	"cordova/http/server"
)

// ipcHandler is a function that processes an IPC request and returns a response.
type ipcHandler func(req ipc.Request) ipc.Response

// fakeDaemon starts a Unix socket listener in a temp dir and dispatches
// incoming IPC requests to handler. Returns the socket path and a cleanup func.
func fakeDaemon(t *testing.T, handler ipcHandler) string {
	t.Helper()
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "test.sock")

	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	t.Cleanup(func() {
		_ = ln.Close()
		_ = os.Remove(sockPath)
	})

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				var req ipc.Request
				if err := json.NewDecoder(c).Decode(&req); err != nil {
					return
				}
				resp := handler(req)
				_ = json.NewEncoder(c).Encode(resp)
			}(conn)
		}
	}()

	return sockPath
}

// newServer wires a fakeDaemon to a server.Handler and returns an httptest.Server.
func newServer(t *testing.T, handler ipcHandler) *httptest.Server {
	t.Helper()
	sockPath := fakeDaemon(t, handler)
	ts := httptest.NewServer(server.Handler(sockPath))
	t.Cleanup(ts.Close)
	return ts
}

// doRequest sends an HTTP request with Basic Auth and returns the response.
func doRequest(t *testing.T, ts *httptest.Server, method, path, body, user, token string) *http.Response {
	t.Helper()
	var bodyReader io.Reader
	if body != "" {
		bodyReader = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, ts.URL+path, bodyReader)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if user != "" {
		req.SetBasicAuth(user, token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	return resp
}

func TestKeyGet_OK(t *testing.T) {
	ts := newServer(t, func(req ipc.Request) ipc.Response {
		data, _ := json.Marshal(ipc.KeyGetData{Name: "foo", Value: "bar"})
		return ipc.Response{OK: true, Data: data}
	})

	resp := doRequest(t, ts, http.MethodGet, "/key/foo", "", "alice", "tok")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	var got ipc.KeyGetData
	_ = json.NewDecoder(resp.Body).Decode(&got)
	if got.Name != "foo" || got.Value != "bar" {
		t.Fatalf("unexpected body: %+v", got)
	}
}

func TestKeyGet_NotFound(t *testing.T) {
	ts := newServer(t, func(req ipc.Request) ipc.Response {
		return ipc.Response{OK: false, Error: "key not found"}
	})

	resp := doRequest(t, ts, http.MethodGet, "/key/missing", "", "alice", "tok")
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", resp.StatusCode)
	}
	var got map[string]string
	_ = json.NewDecoder(resp.Body).Decode(&got)
	if got["error"] != "key not found" {
		t.Fatalf("unexpected error body: %v", got)
	}
}

func TestKeyGet_Unauthorized(t *testing.T) {
	ts := newServer(t, func(req ipc.Request) ipc.Response {
		return ipc.Response{OK: true}
	})

	resp := doRequest(t, ts, http.MethodGet, "/key/foo", "", "", "")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", resp.StatusCode)
	}
}

func TestKeySet_OK(t *testing.T) {
	ts := newServer(t, func(req ipc.Request) ipc.Response {
		data, _ := json.Marshal(ipc.AckData{Message: "ok"})
		return ipc.Response{OK: true, Data: data}
	})

	resp := doRequest(t, ts, http.MethodPut, "/key/foo", `{"value":"baz"}`, "alice", "tok")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}

func TestKeyDelete_OK(t *testing.T) {
	ts := newServer(t, func(req ipc.Request) ipc.Response {
		return ipc.Response{OK: true}
	})

	resp := doRequest(t, ts, http.MethodDelete, "/key/foo", "", "alice", "tok")
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", resp.StatusCode)
	}
}

func TestKeyList_OK(t *testing.T) {
	ts := newServer(t, func(req ipc.Request) ipc.Response {
		data, _ := json.Marshal(ipc.KeyListData{Keys: []string{"a", "b"}})
		return ipc.Response{OK: true, Data: data}
	})

	resp := doRequest(t, ts, http.MethodGet, "/keys", "", "alice", "tok")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	var got ipc.KeyListData
	_ = json.NewDecoder(resp.Body).Decode(&got)
	if len(got.Keys) != 2 || got.Keys[0] != "a" || got.Keys[1] != "b" {
		t.Fatalf("unexpected keys: %v", got.Keys)
	}
}

func TestStatus_OK(t *testing.T) {
	ts := newServer(t, func(req ipc.Request) ipc.Response {
		data, _ := json.Marshal(ipc.StatusData{Sealed: false, Version: "1.0.0"})
		return ipc.Response{OK: true, Data: data}
	})

	resp := doRequest(t, ts, http.MethodGet, "/status", "", "alice", "tok")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	var got ipc.StatusData
	_ = json.NewDecoder(resp.Body).Decode(&got)
	if got.Sealed || got.Version != "1.0.0" {
		t.Fatalf("unexpected status: %+v", got)
	}
}
