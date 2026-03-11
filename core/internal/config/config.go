// cordova/core/internal/config/config.go

package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Cordova CordovaConfig `yaml:"cordova"`
}

type CordovaConfig struct {
	RootSocket string      `yaml:"root_socket"`
	USB        USBConfig   `yaml:"usb"`
	Audit      AuditConfig `yaml:"audit"`
	KDF        KDFConfig   `yaml:"kdf"`
}

type USBConfig struct {
	PrimaryLabel  string `yaml:"primary_label"`
	BackupLabel   string `yaml:"backup_label"`
	MountBase     string `yaml:"mount_base"`
	VaultFilename string `yaml:"vault_filename"`
}

type AuditConfig struct {
	LogPath   string `yaml:"log_path"`
	MaxSizeMB int    `yaml:"max_size_mb"`
}

type KDFConfig struct {
	Time    uint32 `yaml:"argon2id_time"`
	Memory  uint32 `yaml:"argon2id_memory"`
	Threads uint8  `yaml:"argon2id_threads"`
}

// TODO make default an embedded .yaml file
func Defaults() *Config {
	return &Config{
		Cordova: CordovaConfig{
			RootSocket: "/run/cordova/cordova.sock",
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

func Load(path string) (*Config, error) {
	cfg := Defaults()

	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening config: %w", err)
	}
	defer f.Close()

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

func (c *Config) Save(path string) error {
	tmp := path + ".tmp"

	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("creating temp config: %w", err)
	}

	enc := yaml.NewEncoder(f)
	enc.SetIndent(2)
	if err := enc.Encode(c); err != nil {
		f.Close()
		os.Remove(tmp)
		return fmt.Errorf("encoding config: %w", err)
	}
	f.Close()

	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("saving config: %w", err)
	}

	return nil
}

func (c *Config) Validate() error {
	if c.Cordova.RootSocket == "" {
		return fmt.Errorf("root_socket is required")
	}
	return nil
}
