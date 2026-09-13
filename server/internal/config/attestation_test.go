package config

import (
	"os"
	"path/filepath"
	"testing"
)

func setEnv(t *testing.T, kv map[string]string) {
	t.Helper()
	for k, v := range kv {
		t.Setenv(k, v)
	}
}

// The default must produce logs, not silence. An operator who deploys
// without configuring attestation should learn what enforcement would
// have done — 0.13.0's effective default was "nothing happens at all",
// which is how the missing wiring went unnoticed.
func TestDefaultsToPermissive(t *testing.T) {
	for _, k := range []string{
		"ATTESTATION_MODE", "ATTESTATION_ROOTS_PATH",
		"ATTESTATION_REQUIRE_VERIFIED_BOOT", "ATTESTATION_MIN_SECURITY_LEVEL",
		"ATTESTATION_REVOCATION_FAIL_OPEN", "ATTESTATION_EXPECTED_PACKAGES",
	} {
		t.Setenv(k, "")
	}
	c, err := LoadAttestation()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if c.Mode != "permissive" {
		t.Errorf("default mode = %q, want permissive", c.Mode)
	}
	if !c.RequireVerifiedBoot {
		t.Error("verified boot must default ON — a rooted device has genuine attestation")
	}
	if c.RevocationFailOpen {
		t.Error("revocation must default to fail-closed")
	}
}

// Starting in enforce mode with no roots would verify nothing while
// claiming to enforce. Refusing to boot is the only honest option.
func TestEnforceWithoutRootsRefusesToBoot(t *testing.T) {
	setEnv(t, map[string]string{
		"ATTESTATION_MODE":       "enforce",
		"ATTESTATION_ROOTS_PATH": "",
	})
	if _, err := LoadAttestation(); err == nil {
		t.Fatal("enforce with no roots must be rejected at startup")
	}
}

func TestEnforceWithRootsIsAccepted(t *testing.T) {
	path := filepath.Join(t.TempDir(), "roots.pem")
	if err := os.WriteFile(path, []byte("-----BEGIN CERTIFICATE-----\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	setEnv(t, map[string]string{
		"ATTESTATION_MODE":       "enforce",
		"ATTESTATION_ROOTS_PATH": path,
	})
	c, err := LoadAttestation()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if c.Mode != "enforce" {
		t.Errorf("mode = %q", c.Mode)
	}
}

// A typo'd path must fail loudly at startup rather than at the first
// device registration, hours later.
func TestMissingRootsFileIsCaughtAtStartup(t *testing.T) {
	setEnv(t, map[string]string{
		"ATTESTATION_MODE":       "permissive",
		"ATTESTATION_ROOTS_PATH": "/nonexistent/roots.pem",
	})
	if _, err := LoadAttestation(); err == nil {
		t.Fatal("a missing roots file must be reported at startup")
	}
}

func TestInvalidModeRejected(t *testing.T) {
	setEnv(t, map[string]string{"ATTESTATION_MODE": "strict"})
	if _, err := LoadAttestation(); err == nil {
		t.Fatal(`"strict" is not a mode; a typo must not silently disable enforcement`)
	}
}

func TestInvalidSecurityLevelRejected(t *testing.T) {
	setEnv(t, map[string]string{
		"ATTESTATION_MODE":               "permissive",
		"ATTESTATION_MIN_SECURITY_LEVEL": "software",
	})
	if _, err := LoadAttestation(); err == nil {
		t.Fatal("software-backed keys must never be selectable as a floor")
	}
}

func TestExpectedPackagesParsed(t *testing.T) {
	setEnv(t, map[string]string{
		"ATTESTATION_MODE":              "permissive",
		"ATTESTATION_EXPECTED_PACKAGES": " com.a , com.b ,, ",
	})
	c, err := LoadAttestation()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(c.ExpectedPackages) != 2 ||
		c.ExpectedPackages[0] != "com.a" || c.ExpectedPackages[1] != "com.b" {
		t.Errorf("packages = %v", c.ExpectedPackages)
	}
}

func TestVerifiedBootCanBeDisabledExplicitly(t *testing.T) {
	setEnv(t, map[string]string{
		"ATTESTATION_MODE":                  "permissive",
		"ATTESTATION_REQUIRE_VERIFIED_BOOT": "false",
	})
	c, err := LoadAttestation()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if c.RequireVerifiedBoot {
		t.Error("explicit false must be honoured")
	}
}
