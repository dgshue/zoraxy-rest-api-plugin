package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
)

// Config holds plugin configuration for Zoraxy connectivity and bearer token auth.
type Config struct {
	// BearerToken is the token that pipeline callers must provide in the Authorization header.
	BearerToken string `json:"bearer_token"`

	// ZoraxyURL is the base URL of the Zoraxy admin interface (e.g., "http://localhost:8000").
	ZoraxyURL string `json:"zoraxy_url"`

	// ZoraxyUser is the admin username for Zoraxy.
	ZoraxyUser string `json:"zoraxy_user"`

	// ZoraxyPass is the admin password for Zoraxy.
	ZoraxyPass string `json:"zoraxy_pass"`

	// Port overrides the listen port. When set, the plugin ignores
	// Zoraxy's assigned port and uses this instead. Useful for Docker
	// where you need a predictable port for mapping.
	Port int `json:"port,omitempty"`
}

// LoadConfig loads configuration from config.json next to the binary,
// with environment variable overrides.
func LoadConfig() *Config {
	cfg := &Config{
		BearerToken: "changeme",
		ZoraxyURL:   "http://localhost:8000",
		ZoraxyUser:  "admin",
		ZoraxyPass:  "",
	}

	// Try loading from config.json next to the binary
	exePath, err := os.Executable()
	if err == nil {
		configPath := filepath.Join(filepath.Dir(exePath), "config.json")
		if data, err := os.ReadFile(configPath); err == nil {
			if err := json.Unmarshal(data, cfg); err != nil {
				fmt.Fprintf(os.Stderr, "Warning: failed to parse %s: %v\n", configPath, err)
			}
		}
	}

	// Also try config.json in the current working directory
	if data, err := os.ReadFile("config.json"); err == nil {
		if err := json.Unmarshal(data, cfg); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to parse config.json: %v\n", err)
		}
	}

	// Environment variable overrides take precedence
	if v := os.Getenv("LB_MANAGER_TOKEN"); v != "" {
		cfg.BearerToken = v
	}
	if v := os.Getenv("ZORAXY_URL"); v != "" {
		cfg.ZoraxyURL = v
	}
	if v := os.Getenv("ZORAXY_USER"); v != "" {
		cfg.ZoraxyUser = v
	}
	if v := os.Getenv("ZORAXY_PASS"); v != "" {
		cfg.ZoraxyPass = v
	}
	if v := os.Getenv("LB_MANAGER_PORT"); v != "" {
		if p, err := strconv.Atoi(v); err == nil {
			cfg.Port = p
		}
	}

	return cfg
}
