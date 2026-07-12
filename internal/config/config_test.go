package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolveAppliesConfiguredRecordSizeAndDestination(t *testing.T) {
	t.Setenv("CYPHERSTORM_PROFILE", "")
	cfg := Defaults()
	cfg.DefaultRecordSize = "128KiB"
	cfg.DefaultDestination = "/var/backups/cypherstorm"
	policy, err := Resolve(cfg, "")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if policy.RecordSize != 128<<10 {
		t.Fatalf("RecordSize = %d, want %d", policy.RecordSize, 128<<10)
	}
	if policy.DefaultDestination != cfg.DefaultDestination {
		t.Fatalf("DefaultDestination = %q, want %q", policy.DefaultDestination, cfg.DefaultDestination)
	}
}

func TestLoadDoesNotTreatValuesOrCommentsAsSecrets(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	data := "# password rotation documentation\ndefault_destination = '/home/me/passwords/backups'\ndefault_record_size = '64KiB'\n"
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.DefaultDestination != "/home/me/passwords/backups" {
		t.Fatalf("DefaultDestination = %q", cfg.DefaultDestination)
	}
}

func TestContainsSecretKeyChecksOnlyKeys(t *testing.T) {
	if containsSecretKey([]byte("default_destination = '/passwords'\n# private_key is prohibited\n")) {
		t.Fatal("values or comments were classified as secret-bearing keys")
	}
	if !containsSecretKey([]byte("[credentials]\nraw_key = 'secret'\n")) {
		t.Fatal("raw_key key was not rejected")
	}
}

func TestParseByteSize(t *testing.T) {
	for _, test := range []struct {
		value string
		want  uint32
	}{
		{value: "64KiB", want: 64 << 10},
		{value: "1MiB", want: 1 << 20},
		{value: "1024", want: 1024},
	} {
		got, err := parseByteSize(test.value)
		if err != nil || got != test.want {
			t.Fatalf("parseByteSize(%q) = %d, %v; want %d, nil", test.value, got, err, test.want)
		}
	}
}
