// Package config manages non-secret coned-cli settings.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/zzwong/coned-cli/internal/identity"
)

const (
	DefaultBaseURL        = "https://www.coned.com"
	DefaultRequestTimeout = 30 * time.Second
)

// Config contains settings that are safe to persist. Credentials and sessions
// are deliberately managed by securestore instead.
type Selection struct {
	Aliases        map[string]string `json:"aliases,omitempty"`
	DefaultAccount string            `json:"default_account,omitempty"`
	DefaultMeter   string            `json:"default_meter,omitempty"`
}
type Config struct {
	BaseURL        string               `json:"base_url"`
	Profile        string               `json:"profile"`
	RequestTimeout time.Duration        `json:"request_timeout"`
	Selections     map[string]Selection `json:"selections,omitempty"`
}

// Default returns the default configuration.
func Default() Config {
	return Config{BaseURL: DefaultBaseURL, Profile: "default", RequestTimeout: DefaultRequestTimeout}
}

// DefaultConfig is an alias for Default for callers that prefer a descriptive name.
func DefaultConfig() Config { return Default() }

// DefaultPath is the OS-specific location for the non-secret configuration.
func DefaultPath() string {
	dir, err := os.UserConfigDir()
	if err != nil {
		return filepath.Join(".config", "coned", "config.json")
	}
	return filepath.Join(dir, "coned", "config.json")
}

// Load reads a configuration file. A missing file returns the defaults.
func Load(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return Default(), nil
	}
	if err != nil {
		return Config{}, fmt.Errorf("read config: %w", err)
	}

	cfg := Default()
	if err := json.Unmarshal(data, &cfg); err != nil {
		return Config{}, fmt.Errorf("decode config: %w", err)
	}
	if err := validate(cfg); err != nil {
		return Config{}, fmt.Errorf("validate config: %w", err)
	}
	return cfg, nil
}

func validate(cfg Config) error {
	parsedURL, err := url.Parse(cfg.BaseURL)
	if err != nil || parsedURL.Scheme == "" || parsedURL.Host == "" {
		return fmt.Errorf("base_url must be an absolute URL")
	}
	if strings.TrimSpace(cfg.Profile) == "" {
		return fmt.Errorf("profile must not be empty")
	}
	if cfg.RequestTimeout <= 0 {
		return fmt.Errorf("request_timeout must be positive")
	}
	for profile, selection := range cfg.Selections {
		if strings.TrimSpace(profile) == "" {
			return fmt.Errorf("selection profile must not be empty")
		}
		for alias, handle := range selection.Aliases {
			if !identity.ValidAlias(alias) || !validHandle(handle) {
				return fmt.Errorf("invalid entity alias")
			}
		}
		if selection.DefaultAccount != "" && !validHandle(selection.DefaultAccount) {
			return fmt.Errorf("invalid default account")
		}
		if selection.DefaultMeter != "" && !validHandle(selection.DefaultMeter) {
			return fmt.Errorf("invalid default meter")
		}
	}
	return nil
}

func validHandle(v string) bool {
	for _, prefix := range []string{"account-", "premise-", "meter-", "register-"} {
		if strings.HasPrefix(v, prefix) && len(v) > len(prefix) {
			return true
		}
	}
	return false
}

// Save atomically writes the non-secret configuration with owner-only access.
func (c Config) Save(path string) error {
	if err := validate(c); err != nil {
		return fmt.Errorf("validate config: %w", err)
	}

	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Errorf("encode config: %w", err)
	}
	data = append(data, '\n')

	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return fmt.Errorf("create config directory: %w", err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".config-*.tmp")
	if err != nil {
		return fmt.Errorf("create temporary config: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	if err := tmp.Chmod(0600); err != nil {
		tmp.Close()
		return fmt.Errorf("set config permissions: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("write config: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("sync config: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close config: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("replace config: %w", err)
	}
	return nil
}
