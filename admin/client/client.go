// cordova/admin/client/client.go
//
// Package client provides a thin wrapper around the cordova-vault Unix socket
// IPC protocol. Both the CLI and TUI packages import this package so that all
// network logic lives in one place.

package client

import (
	"encoding/json"
	"fmt"
	"net"
	"time"

	"cordova/core/ipc"
)

const (
	// dialTimeout is the maximum time to wait when connecting to the socket.
	dialTimeout = 5 * time.Second

	// requestTimeout is the maximum time allowed for a full request/response
	// cycle after the connection is established.
	requestTimeout = 30 * time.Second
)

// Client holds the connection parameters needed to talk to cordova-vault.
type Client struct {
	// socketPath is the filesystem path of the cordova-vault Unix domain socket.
	socketPath string

	// token is the bearer credential sent with every request. May be the
	// ephemeral root token or a persistent admin token.
	token string
}

// New creates a Client that will connect to socketPath and authenticate with
// token on every request.
func New(socketPath, token string) *Client {
	return &Client{socketPath: socketPath, token: token}
}

// Probe dials the socket and immediately closes the connection. It is used to
// verify that the daemon is reachable before launching the TUI, so a missing
// socket produces a clear error at startup rather than inside the UI.
func (c *Client) Probe() error {
	dialer := net.Dialer{Timeout: dialTimeout}
	conn, err := dialer.Dial("unix", c.socketPath)
	if err != nil {
		return fmt.Errorf("connecting to daemon at %s: %w", c.socketPath, err)
	}
	conn.Close()
	return nil
}

// Send dials the Unix socket, encodes req as JSON, reads one JSON response,
// and closes the connection. Each call opens and closes its own connection.
func (c *Client) Send(cmd string, params any) (*ipc.Response, error) {
	var rawParams json.RawMessage
	if params != nil {
		b, err := json.Marshal(params)
		if err != nil {
			return nil, fmt.Errorf("encoding params: %w", err)
		}
		rawParams = b
	}

	req := ipc.Request{
		Token:   c.token,
		Command: cmd,
		Params:  rawParams,
	}

	dialer := net.Dialer{Timeout: dialTimeout}
	conn, err := dialer.Dial("unix", c.socketPath)
	if err != nil {
		return nil, fmt.Errorf("connecting to daemon at %s: %w", c.socketPath, err)
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(requestTimeout)) //nolint:errcheck

	if err := json.NewEncoder(conn).Encode(req); err != nil {
		return nil, fmt.Errorf("sending request: %w", err)
	}

	var resp ipc.Response
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	return &resp, nil
}
