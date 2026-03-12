// cordova/admin/client/client.go

package client

import (
	"encoding/json"
	"fmt"
	"net"
	"time"

	"cordova/core/ipc"
)

const (
	dialTimeout    = 5 * time.Second
	requestTimeout = 30 * time.Second
)

// Client is a shared IPC connection used by both the CLI and TUI.
type Client struct {
	socketPath string
	username   string
	token      string
}

// New creates a Client with the given socket path, username, and token.
func New(socketPath, username, token string) *Client {
	return &Client{socketPath: socketPath, username: username, token: token}
}

// Probe opens a connection to verify the daemon is reachable.
func (c *Client) Probe() error {
	dialer := net.Dialer{Timeout: dialTimeout}
	conn, err := dialer.Dial("unix", c.socketPath)
	if err != nil {
		return fmt.Errorf("connecting to daemon at %s: %w", c.socketPath, err)
	}
	_ = conn.Close()
	return nil
}

// Send transmits a command with optional params and returns the daemon's
// response.
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
		Username: c.username,
		Token:    c.token,
		Command:  cmd,
		Params:   rawParams,
	}

	dialer := net.Dialer{Timeout: dialTimeout}
	conn, err := dialer.Dial("unix", c.socketPath)
	if err != nil {
		return nil, fmt.Errorf("connecting to daemon at %s: %w", c.socketPath, err)
	}
	defer func() { _ = conn.Close() }()

	if err := conn.SetDeadline(time.Now().Add(requestTimeout)); err != nil {
		return nil, fmt.Errorf("setting deadline: %w", err)
	}

	if err := json.NewEncoder(conn).Encode(req); err != nil {
		return nil, fmt.Errorf("sending request: %w", err)
	}

	var resp ipc.Response
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	return &resp, nil
}

// Username returns the username this client authenticates as.
func (c *Client) Username() string { return c.username }
