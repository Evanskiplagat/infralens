package config

import "testing"

func TestLoadPrecedence(t *testing.T) {
	t.Setenv("AWS_PROFILE", "env-profile")
	t.Setenv("AWS_REGION", "us-east-1")
	t.Setenv("INFRALENS_DB_PATH", "")
	t.Setenv("INFRALENS_LOG_LEVEL", "")
	t.Setenv("HOME", t.TempDir())
	t.Setenv("USERPROFILE", t.TempDir())

	cfg, err := Load(Config{})
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if cfg.AWSProfile != "env-profile" {
		t.Errorf("expected env var to set AWSProfile, got %q", cfg.AWSProfile)
	}
	if cfg.DBPath != "infralens.db" {
		t.Errorf("expected default DBPath to survive, got %q", cfg.DBPath)
	}

	cfg, err = Load(Config{AWSProfile: "flag-profile"})
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if cfg.AWSProfile != "flag-profile" {
		t.Errorf("expected override to win over env var, got %q", cfg.AWSProfile)
	}
}
