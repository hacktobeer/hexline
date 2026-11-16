package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDefaultsAreValid(t *testing.T) {
	if err := Default().Validate(); err != nil {
		t.Fatalf("defaults invalid: %v", err)
	}
}

func TestLoadExampleFile(t *testing.T) {
	cfg, err := Load("../../hexline.example.toml")
	if err != nil {
		t.Fatalf("example config: %v", err)
	}
	if cfg.Transport.SSH.Address != ":2222" {
		t.Errorf("address = %q", cfg.Transport.SSH.Address)
	}
	if cfg.Probation.Days != 3 || cfg.Probation.Posts != 10 {
		t.Errorf("probation defaults drifted: %+v", cfg.Probation)
	}
	if !strings.Contains(cfg.UI.MOTD, "hexline") {
		t.Errorf("motd not loaded: %q", cfg.UI.MOTD)
	}
}

func TestUnknownKeyRejected(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.toml")
	if err := os.WriteFile(path, []byte("[server]\nname = \"x\"\ntypo_key = 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := Load(path)
	if err == nil || !strings.Contains(err.Error(), "typo_key") {
		t.Fatalf("want unknown-key error, got %v", err)
	}
}

func TestInvalidValuesNameTheKey(t *testing.T) {
	cfg := Default()
	cfg.Transport.SSH.Address = ""
	cfg.Limits.PostRatePerHour = 0
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected validation error")
	}
	for _, want := range []string{"transport.ssh.address", "limits.post_rate_per_hour"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q missing %q", err, want)
		}
	}
}

func TestEnvOverrides(t *testing.T) {
	t.Setenv("HEXLINE_DATA_DIR", "/tmp/hexline-test")
	t.Setenv("HEXLINE_SSH_ADDRESS", "127.0.0.1:2299")
	t.Setenv("HEXLINE_SSH_IDLE_TIMEOUT", "5m")
	t.Setenv("HEXLINE_REGISTRATION_OPEN", "false")
	t.Setenv("HEXLINE_PROBATION_POSTS", "3")

	cfg, err := LoadOrDefault(filepath.Join(t.TempDir(), "absent.toml"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Server.DataDir != "/tmp/hexline-test" || cfg.Transport.SSH.Address != "127.0.0.1:2299" {
		t.Fatalf("env not applied: %+v", cfg)
	}
	if cfg.Transport.SSH.IdleTimeout != 5*time.Minute {
		t.Errorf("idle timeout = %s", cfg.Transport.SSH.IdleTimeout)
	}
	if cfg.Registration.Open {
		t.Error("registration should be closed")
	}
	if cfg.Probation.Posts != 3 {
		t.Errorf("probation posts = %d", cfg.Probation.Posts)
	}
	if got := cfg.DBPath(); got != "/tmp/hexline-test/hexline.db" {
		t.Errorf("DBPath = %q", got)
	}
}

func TestAbsPath(t *testing.T) {
	cfg := Default()
	cfg.Server.DataDir = "/srv/hexline"
	if got := cfg.AbsPath("files"); got != "/srv/hexline/files" {
		t.Errorf("relative = %q", got)
	}
	if got := cfg.AbsPath("/var/tmp/x"); got != "/var/tmp/x" {
		t.Errorf("absolute = %q", got)
	}
}

func TestMissingConfigFileIsAnError(t *testing.T) {
	if _, err := Load(filepath.Join(t.TempDir(), "nope.toml")); err == nil {
		t.Fatal("expected error for missing config")
	}
}

func TestGuestToggleViaEnv(t *testing.T) {
	t.Setenv("HEXLINE_GUEST", "false")
	cfg, err := LoadOrDefault(filepath.Join(t.TempDir(), "absent.toml"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Guest.Enabled {
		t.Fatal("guest should be disabled via HEXLINE_GUEST=false")
	}
	if Default().Guest.Enabled != true {
		t.Fatal("guest default should stay enabled for backward compatibility")
	}
}
