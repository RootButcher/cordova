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

type Client struct {
	socketPath string
	token      string
}

func New(socketPath, token string) *Client {
	return &Client{socketPath: socketPath, token: token}
}
func (c *Client) Probe() error {
	dialer := net.Dialer{Timeout: dialTimeout}
	conn, err := dialer.Dial("unix", c.socketPath)
	if err != nil {
		return fmt.Errorf("connecting to daemon at %s: %w", c.socketPath, err)
	}
	conn.Close()
	return nil
}
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

	conn.SetDeadline(time.Now().Add(requestTimeout))

	if err := json.NewEncoder(conn).Encode(req); err != nil {
		return nil, fmt.Errorf("sending request: %w", err)
	}

	var resp ipc.Response
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	return &resp, nil
}
