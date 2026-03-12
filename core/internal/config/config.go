// cordova/core/internal/config/config.go

package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Config is the top-level configuration structure.
type Config struct {
	Cordova CordovaConfig `yaml:"cordova"`
}

// CordovaConfig holds all daemon configuration.
type CordovaConfig struct {
	SocketsConfig string      `yaml:"sockets_config"`
	UsersFilename string      `yaml:"users_filename"`
	USB           USBConfig   `yaml:"usb"`
	Audit         AuditConfig `yaml:"audit"`
	KDF           KDFConfig   `yaml:"kdf"`
}

// USBConfig describes the vault media (USB drive or mount point).
type USBConfig struct {
	PrimaryLabel  string `yaml:"primary_label"`
	BackupLabel   string `yaml:"backup_label"`
	MountBase     string `yaml:"mount_base"`
	VaultFilename string `yaml:"vault_filename"`
}

// AuditConfig controls audit log behaviour.
type AuditConfig struct {
	LogPath   string `yaml:"log_path"`
	MaxSizeMB int    `yaml:"max_size_mb"`
}

// KDFConfig holds Argon2id parameters.
type KDFConfig struct {
	Time    uint32 `yaml:"argon2id_time"`
	Memory  uint32 `yaml:"argon2id_memory"`
	Threads uint8  `yaml:"argon2id_threads"`
}

// Defaults returns a Config populated with safe production defaults.
func Defaults() *Config {
	return &Config{
		Cordova: CordovaConfig{
			SocketsConfig: "",
			UsersFilename: "cordova.users",
			USB: USBConfig{
				PrimaryLabel:  "CORDOVA-KEYS",
				BackupLabel:   "CORDOVA-BACKUP",
				MountBase:     "/mnt/cordova/keys",
				VaultFilename: "cordova.vault",
			},
			Audit: AuditConfig{
				LogPath:   "/var/log/cordova/audit.log",
				MaxSizeMB: 100,
			},
			KDF: KDFConfig{
				Time:    1,
				Memory:  65536,
				Threads: 2,
			},
		},
	}
}

// Load parses the YAML file at path over the defaults.
func Load(path string) (*Config, error) {
	cfg := Defaults()

	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening config: %w", err)
	}
	defer func(f *os.File) {
		_ = f.Close()
	}(f)

	dec := yaml.NewDecoder(f)
	dec.KnownFields(true)
	if err := dec.Decode(cfg); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	return cfg, nil
}

// Save atomically writes the config to path.
func (c *Config) Save(path string) error {
	tmp := path + ".tmp"

	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("creating temp config: %w", err)
	}

	enc := yaml.NewEncoder(f)
	enc.SetIndent(2)
	if err := enc.Encode(c); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("encoding config: %w", err)
	}
	_ = f.Close()

	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("saving config: %w", err)
	}

	return nil
}

// Validate checks that required config fields are set.
func (c *Config) Validate() error {
	if c.Cordova.UsersFilename == "" {
		return fmt.Errorf("users_filename is required")
	}
	return nil
}