package config

import (
	"fmt"
	"os"
	"strings"
)

// AttestationConfig configures hardware attestation enforcement.
//
// This exists because 0.13.0 shipped the enforcement machinery without
// it. The gate, the verifier, the boot-state parser and the revocation
// checker were all written, tested and unreachable: nothing read an
// environment variable and nothing called SetAttestationGate. The
// walkthrough document told operators to set ATTESTATION_MODE, which did
// nothing at all.
//
// It is the third instance of the same failure in this codebase —
// `allowed_ips` hardcoded to empty in 0.10.0, `GetEffectiveAllowedIPs`
// as dead code, and now this. The pattern is: build the mechanism, test
// the mechanism, forget the one line that connects it. Worth naming so
// the next feature gets a wiring check before it gets a test.
type AttestationConfig struct {
	// Mode is "off", "permissive" or "enforce".
	//
	// Defaults to "permissive" rather than "off": an operator who
	// deploys without configuring anything should get logs telling them
	// what enforcement *would* have done, not silence. Defaulting to
	// "enforce" would lock out a fleet on first upgrade.
	Mode string

	// RootsPath points at a PEM bundle of Google's hardware attestation
	// root certificates.
	//
	// Deliberately not bundled into the binary. Google rotates these,
	// and a stale root compiled into a release either rejects new
	// devices or — worse — gets patched around by an operator disabling
	// attestation entirely. Fetch them from
	// https://developer.android.com/privacy-and-security/security-key-attestation
	// and mount the file.
	RootsPath string

	// RequireVerifiedBoot rejects unlocked bootloaders and non-verified
	// boot states. Default true: a rooted handset has genuine hardware
	// attestation, so without this check it enrols cleanly.
	RequireVerifiedBoot bool

	// MinSecurityLevel is "trusted_environment" or "strongbox".
	// Software-backed keys are always rejected.
	MinSecurityLevel string

	// RevocationURL overrides Google's status list endpoint. Useful for
	// an internal mirror on a restricted network.
	RevocationURL string

	// RevocationFailOpen admits devices when the status list cannot be
	// fetched and nothing is cached.
	//
	// Default false. An air-gapped controller must either set this or
	// mirror the list, and we would rather that be a decision than a
	// surprise: the alternative default silently downgrades revocation
	// checking to nothing the first time egress is blocked.
	RevocationFailOpen bool

	// ExpectedPackages, when set, requires the attested package name to
	// match. Without it, any app on a genuine device produces a chain
	// that verifies — including one that is not ours.
	ExpectedPackages []string

	// PlayIntegrity configures the second, complementary gate.
	PlayIntegrity PlayIntegrityConfig
}

// PlayIntegrityConfig configures Google Play Integrity verification.
//
// Separate from the hardware-attestation settings above because the two
// answer different questions and a deployment reasonably runs one without
// the other: an MDM-distributed hospital build is not on Play at all, so
// Play Integrity may be off while hardware attestation enforces.
type PlayIntegrityConfig struct {
	// Mode is "off" (default), "permissive" or "enforce".
	//
	// Defaults to off rather than permissive — unlike hardware
	// attestation — because it needs credentials to do anything at all.
	// A permissive default would log a decode failure on every single
	// registration for every deployment that never configured it.
	Mode string

	// ServiceAccountPath is a Google service-account JSON key with the
	// playintegrity scope. Required for any mode but "off".
	ServiceAccountPath string

	// PackageName is the app the tokens are minted for.
	PackageName string

	// MinDeviceIntegrity is "basic", "device" (default) or "strong".
	MinDeviceIntegrity string

	// AllowSideloaded treats UNRECOGNIZED_VERSION as a warning instead of
	// a failure.
	//
	// Defaults TRUE, which is the opposite of the library default and
	// deliberate: a hospital build distributed by MDM is sideloaded by
	// definition, so the strict reading would refuse every device in the
	// deployment this product targets.
	AllowSideloaded bool

	// TreatWarningAsFailure makes enforce mode refuse on warnings too.
	TreatWarningAsFailure bool
}

// LoadAttestation reads attestation settings from the environment.
func LoadAttestation() (AttestationConfig, error) {
	c := AttestationConfig{
		Mode:                envOr("ATTESTATION_MODE", "permissive"),
		RootsPath:           os.Getenv("ATTESTATION_ROOTS_PATH"),
		RequireVerifiedBoot: envBool("ATTESTATION_REQUIRE_VERIFIED_BOOT", true),
		MinSecurityLevel:    envOr("ATTESTATION_MIN_SECURITY_LEVEL", "trusted_environment"),
		RevocationURL:       os.Getenv("ATTESTATION_REVOCATION_URL"),
		RevocationFailOpen:  envBool("ATTESTATION_REVOCATION_FAIL_OPEN", false),
	}
	c.PlayIntegrity = PlayIntegrityConfig{
		Mode:                  envOr("PLAY_INTEGRITY_MODE", "off"),
		ServiceAccountPath:    os.Getenv("PLAY_INTEGRITY_SERVICE_ACCOUNT"),
		PackageName:           os.Getenv("PLAY_INTEGRITY_PACKAGE"),
		MinDeviceIntegrity:    envOr("PLAY_INTEGRITY_MIN_DEVICE", "device"),
		AllowSideloaded:       envBool("PLAY_INTEGRITY_ALLOW_SIDELOADED", true),
		TreatWarningAsFailure: envBool("PLAY_INTEGRITY_WARNING_IS_FAILURE", false),
	}

	if pkgs := os.Getenv("ATTESTATION_EXPECTED_PACKAGES"); pkgs != "" {
		for _, p := range strings.Split(pkgs, ",") {
			if p = strings.TrimSpace(p); p != "" {
				c.ExpectedPackages = append(c.ExpectedPackages, p)
			}
		}
	}

	switch c.Mode {
	case "off", "permissive", "enforce":
	default:
		return c, fmt.Errorf(
			"ATTESTATION_MODE must be off, permissive or enforce (got %q)", c.Mode)
	}
	switch c.MinSecurityLevel {
	case "trusted_environment", "strongbox":
	default:
		return c, fmt.Errorf(
			"ATTESTATION_MIN_SECURITY_LEVEL must be trusted_environment or strongbox (got %q)",
			c.MinSecurityLevel)
	}

	// Refuse to boot in a configuration that cannot do what it claims.
	// Starting in enforce mode with no roots would verify nothing while
	// reporting that it enforces — the worst of both.
	if c.Mode == "enforce" && c.RootsPath == "" {
		return c, fmt.Errorf(
			"ATTESTATION_MODE=enforce requires ATTESTATION_ROOTS_PATH " +
				"(a PEM bundle of Google's hardware attestation roots); " +
				"see docs/attestation-deployment-ko.md")
	}
	if c.RootsPath != "" {
		if _, err := os.Stat(c.RootsPath); err != nil {
			return c, fmt.Errorf("ATTESTATION_ROOTS_PATH %q: %w", c.RootsPath, err)
		}
	}

	pi := c.PlayIntegrity
	switch pi.Mode {
	case "off", "permissive", "enforce":
	default:
		return c, fmt.Errorf(
			"PLAY_INTEGRITY_MODE must be off, permissive or enforce (got %q)", pi.Mode)
	}
	switch pi.MinDeviceIntegrity {
	case "basic", "device", "strong":
	default:
		return c, fmt.Errorf(
			"PLAY_INTEGRITY_MIN_DEVICE must be basic, device or strong (got %q)",
			pi.MinDeviceIntegrity)
	}
	if pi.Mode != "off" {
		// Same reasoning as the attestation roots check: a mode that
		// cannot do what it claims must not start. Without credentials
		// every token decode fails, so enforce would refuse the entire
		// fleet and permissive would log an error per registration
		// forever.
		if pi.ServiceAccountPath == "" {
			return c, fmt.Errorf(
				"PLAY_INTEGRITY_MODE=%s requires PLAY_INTEGRITY_SERVICE_ACCOUNT", pi.Mode)
		}
		if _, err := os.Stat(pi.ServiceAccountPath); err != nil {
			return c, fmt.Errorf("PLAY_INTEGRITY_SERVICE_ACCOUNT %q: %w",
				pi.ServiceAccountPath, err)
		}
		if pi.PackageName == "" {
			return c, fmt.Errorf(
				"PLAY_INTEGRITY_MODE=%s requires PLAY_INTEGRITY_PACKAGE", pi.Mode)
		}
	}
	return c, nil
}

func envOr(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
}

func envBool(key string, def bool) bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv(key)))
	switch v {
	case "":
		return def
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		return def
	}
}
