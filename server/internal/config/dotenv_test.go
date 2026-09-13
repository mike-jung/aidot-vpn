package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadDotEnvFrom(t *testing.T) {
	dir := t.TempDir()
	envFile := filepath.Join(dir, ".env")
	contents := `# AidotVpn test .env
MARIADB_ROOT_PASSWORD=secret_root_pw
AIDOTVPN_DB_USER=aidotvpn
AIDOTVPN_DB_PASSWORD="quoted-value"
EMPTY_VALUE=
KEY_WITH_EQUALS=base64==
export EXPORTED_VAR=hello

# blank line above is fine
`
	if err := os.WriteFile(envFile, []byte(contents), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	// Pre-set one variable to verify "existing env wins" rule.
	t.Setenv("AIDOTVPN_DB_USER", "preset")

	path, count, err := LoadDotEnvFrom(dir)
	if err != nil {
		t.Fatalf("LoadDotEnvFrom: %v", err)
	}
	if path != envFile {
		t.Errorf("path: got %q want %q", path, envFile)
	}

	// We set 5 of the 6 (AIDOTVPN_DB_USER was already set so skipped).
	if count != 5 {
		t.Errorf("count: got %d want 5", count)
	}

	if got := os.Getenv("MARIADB_ROOT_PASSWORD"); got != "secret_root_pw" {
		t.Errorf("MARIADB_ROOT_PASSWORD: %q", got)
	}
	if got := os.Getenv("AIDOTVPN_DB_USER"); got != "preset" {
		t.Errorf("preset should win, got %q", got)
	}
	if got := os.Getenv("AIDOTVPN_DB_PASSWORD"); got != "quoted-value" {
		t.Errorf("quotes not stripped: %q", got)
	}
	if got := os.Getenv("KEY_WITH_EQUALS"); got != "base64==" {
		t.Errorf("KEY_WITH_EQUALS: %q (want base64==)", got)
	}
	if got := os.Getenv("EXPORTED_VAR"); got != "hello" {
		t.Errorf("EXPORTED_VAR: %q", got)
	}
}

func TestLoadDotEnvFromMissing(t *testing.T) {
	dir := t.TempDir()
	// Force the parent search to terminate at this temp dir by making sure
	// no .env exists anywhere up the tree. tempdirs are typically /tmp/...
	// so an actual .env at filesystem root is unlikely; if a CI runner
	// somehow has one, this test would fail spuriously.
	path, count, err := LoadDotEnvFrom(dir)
	if err != nil {
		t.Fatalf("err on missing: %v", err)
	}
	if path != "" || count != 0 {
		t.Errorf("missing: got path=%q count=%d, want empty", path, count)
	}
}

func TestLoadDotEnvParentDir(t *testing.T) {
	parent := t.TempDir()
	child := filepath.Join(parent, "subdir")
	if err := os.MkdirAll(child, 0o755); err != nil {
		t.Fatal(err)
	}
	envFile := filepath.Join(parent, ".env")
	if err := os.WriteFile(envFile, []byte("FOUND_IN_PARENT=yes\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	t.Setenv("FOUND_IN_PARENT", "")
	if err := os.Unsetenv("FOUND_IN_PARENT"); err != nil {
		t.Fatal(err)
	}

	path, _, err := LoadDotEnvFrom(child)
	if err != nil {
		t.Fatalf("LoadDotEnvFrom: %v", err)
	}
	if path != envFile {
		t.Errorf("expected to find %q from child dir, got %q", envFile, path)
	}
	if got := os.Getenv("FOUND_IN_PARENT"); got != "yes" {
		t.Errorf("FOUND_IN_PARENT: %q", got)
	}
}

func TestLoadDotEnvSyntaxErrors(t *testing.T) {
	cases := map[string]string{
		"missing equals":  "INVALID_LINE\n",
		"empty key":       "=value\n",
		"key with space":  "BAD KEY=value\n",
		"key starts num":  "1KEY=value\n",
		"key with hyphen": "BAD-KEY=value\n",
	}
	for name, contents := range cases {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			envFile := filepath.Join(dir, ".env")
			if err := os.WriteFile(envFile, []byte(contents), 0o644); err != nil {
				t.Fatal(err)
			}
			_, _, err := LoadDotEnvFrom(dir)
			if err == nil {
				t.Errorf("expected error for %q", contents)
			}
		})
	}
}

func TestLoadDotEnvBOM(t *testing.T) {
	dir := t.TempDir()
	envFile := filepath.Join(dir, ".env")
	// UTF-8 BOM (EF BB BF) followed by a normal KEY=VALUE.
	contents := "\uFEFFNOTEPAD_KEY=ok\n"
	if err := os.WriteFile(envFile, []byte(contents), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Unsetenv("NOTEPAD_KEY"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadDotEnvFrom(dir); err != nil {
		t.Fatalf("LoadDotEnvFrom: %v", err)
	}
	if got := os.Getenv("NOTEPAD_KEY"); got != "ok" {
		t.Errorf("BOM not stripped, key not set or has BOM in name: %q", got)
	}
}

func TestExplicitDotEnv(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "controller.env")
	if err := os.WriteFile(file, []byte("AIDOT_TEST_EXPLICIT_ENV=loaded\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AIDOTVPN_ENV_FILE", file)
	p, n, err := LoadDotEnv()
	if err != nil || p != file || n != 1 {
		t.Fatalf("explicit load: %s %d %v", p, n, err)
	}
	t.Cleanup(func() { os.Unsetenv("AIDOT_TEST_EXPLICIT_ENV") })
	t.Setenv("AIDOTVPN_ENV_FILE", "")
	p, n, err = LoadDotEnv()
	if p != "" || n != 0 || err != nil {
		t.Fatal("empty override must disable discovery")
	}
	t.Setenv("AIDOTVPN_ENV_FILE", "relative.env")
	if _, _, err = LoadDotEnv(); err == nil {
		t.Fatal("relative path accepted")
	}
	t.Setenv("AIDOTVPN_ENV_FILE", filepath.Join(dir, "missing.env"))
	if _, _, err = LoadDotEnv(); err == nil {
		t.Fatal("missing explicit config accepted")
	}
}
