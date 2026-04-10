package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadDotEnvParsesFileAndRespectsExistingEnv(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".env")
	contents := `# a comment line
PORT=9000
PUBLIC_BASE_URL = "http://localhost:9000"
QUOTED='single quoted value'
WITH_INLINE_COMMENT=plainvalue # trailing comment
export EXPORTED_KEY=exported-value

ALREADY_SET=from-file
`
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("write .env: %v", err)
	}

	// Pre-set one env var to verify dotenv does NOT overwrite it.
	t.Setenv("ALREADY_SET", "from-shell")
	// Ensure the others are unset to start.
	for _, k := range []string{"PORT", "PUBLIC_BASE_URL", "QUOTED", "WITH_INLINE_COMMENT", "EXPORTED_KEY"} {
		t.Setenv(k, "")
		_ = os.Unsetenv(k)
	}

	if err := LoadDotEnv(path); err != nil {
		t.Fatalf("LoadDotEnv: %v", err)
	}

	cases := map[string]string{
		"PORT":                "9000",
		"PUBLIC_BASE_URL":     "http://localhost:9000",
		"QUOTED":              "single quoted value",
		"WITH_INLINE_COMMENT": "plainvalue",
		"EXPORTED_KEY":        "exported-value",
		"ALREADY_SET":         "from-shell", // shell value must win
	}
	for k, want := range cases {
		if got := os.Getenv(k); got != want {
			t.Errorf("env %s: got %q want %q", k, got, want)
		}
	}
}

func TestLoadDotEnvMissingFileIsNotAnError(t *testing.T) {
	if err := LoadDotEnv(filepath.Join(t.TempDir(), "does-not-exist.env")); err != nil {
		t.Fatalf("expected nil for missing file, got %v", err)
	}
}

func TestLoadDotEnvRejectsMalformedLine(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".env")
	if err := os.WriteFile(path, []byte("not-a-key-value-line\n"), 0o600); err != nil {
		t.Fatalf("write .env: %v", err)
	}
	if err := LoadDotEnv(path); err == nil {
		t.Fatalf("expected parse error for malformed line")
	}
}
