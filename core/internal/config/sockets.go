// cordova/core/internal/config/sockets.go

package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// SocketsConfig is the top-level structure of sockets.yaml.
type SocketsConfig struct {
	Sockets []SocketEntry `yaml:"sockets"`
}

// SocketEntry describes a single Unix socket listener.
type SocketEntry struct {
	Name  string      `yaml:"name"`
	Path  string      `yaml:"path"`
	Scope SocketScope `yaml:"scope"`
}

// SocketScope defines what operations are permitted on a socket.
// An unrestricted socket allows all operations. A restricted socket limits
// key access to the listed namespaces and/or keys.
type SocketScope struct {
	Unrestricted bool     `yaml:"unrestricted"`
	Namespaces   []string `yaml:"namespaces,omitempty"`
	Keys         []string `yaml:"keys,omitempty"`
	Writable     bool     `yaml:"writable"`
}

// LoadSockets parses the sockets.yaml file at path.
// If path is empty it returns an empty SocketsConfig (no static sockets).
func LoadSockets(path string) (*SocketsConfig, error) {
	if path == "" {
		return &SocketsConfig{}, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &SocketsConfig{}, nil
		}
		return nil, fmt.Errorf("reading sockets config: %w", err)
	}

	var sc SocketsConfig
	if err := yaml.Unmarshal(data, &sc); err != nil {
		return nil, fmt.Errorf("parsing sockets config: %w", err)
	}
	return &sc, nil
}

// SaveSockets atomically writes sc to path.
func SaveSockets(path string, sc *SocketsConfig) error {
	if path == "" {
		return fmt.Errorf("sockets_config path is not set")
	}
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("creating temp sockets config: %w", err)
	}
	enc := yaml.NewEncoder(f)
	enc.SetIndent(2)
	if err := enc.Encode(sc); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("encoding sockets config: %w", err)
	}
	_ = f.Close()
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("saving sockets config: %w", err)
	}
	return nil
}
