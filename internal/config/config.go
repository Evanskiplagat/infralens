// Package config resolves InfraLens's runtime configuration from, in
// increasing priority: built-in defaults, an optional
// ~/.infralens/config.json file, environment variables, and explicit
// overrides (typically parsed CLI flags).
package config

import (
	"encoding/json"
	"os"
	"path/filepath"
)

// Config holds the settings shared across CLI commands.
type Config struct {
	AWSProfile string `json:"aws_profile,omitempty"`
	AWSRegion  string `json:"aws_region,omitempty"`
	DBPath     string `json:"db_path,omitempty"`
	LogLevel   string `json:"log_level,omitempty"`
}

// Default returns InfraLens's built-in configuration defaults.
func Default() Config {
	return Config{
		DBPath:   "infralens.db",
		LogLevel: "info",
	}
}

// Load merges defaults, the optional config file, environment variables,
// and overrides, in that order, so each layer can override the last.
func Load(overrides Config) (Config, error) {
	cfg := Default()

	if home, err := os.UserHomeDir(); err == nil {
		path := filepath.Join(home, ".infralens", "config.json")
		if data, err := os.ReadFile(path); err == nil {
			var fileCfg Config
			if err := json.Unmarshal(data, &fileCfg); err != nil {
				return Config{}, err
			}
			cfg = merge(cfg, fileCfg)
		}
	}

	cfg = merge(cfg, Config{
		AWSProfile: os.Getenv("AWS_PROFILE"),
		AWSRegion:  os.Getenv("AWS_REGION"),
		DBPath:     os.Getenv("INFRALENS_DB_PATH"),
		LogLevel:   os.Getenv("INFRALENS_LOG_LEVEL"),
	})

	cfg = merge(cfg, overrides)
	return cfg, nil
}

func merge(base, override Config) Config {
	if override.AWSProfile != "" {
		base.AWSProfile = override.AWSProfile
	}
	if override.AWSRegion != "" {
		base.AWSRegion = override.AWSRegion
	}
	if override.DBPath != "" {
		base.DBPath = override.DBPath
	}
	if override.LogLevel != "" {
		base.LogLevel = override.LogLevel
	}
	return base
}
