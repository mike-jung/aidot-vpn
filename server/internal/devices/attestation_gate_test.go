package devices

import (
	"context"
	"errors"
	"testing"

	"github.com/aidotvpn/server/internal/attestation"
)

func challengeOK(_ context.Context, _ string) ([]byte, error) {
	return make([]byte, attestation.ChallengeBytes), nil
}

func challengeMissing(_ context.Context, _ string) ([]byte, error) {
	return nil, errors.New("no challenge on file")
}

// The regression this release exists to prevent. Before 0.13.0 any
// non-empty attestation_token marked a device active, and the chain was
// never even passed in. A device sending nothing must not be admitted
// under enforcement.
func TestEnforceRejectsMissingChain(t *testing.T) {
	g := &AttestationGate{
		Mode:         AttestationEnforce,
		Verifier:     attestation.New(),
		ChallengeFor: challengeOK,
	}
	out, err := g.Verify(context.Background(), "install-1", nil)
	if err == nil {
		t.Fatal("enforce mode must refuse a registration with no chain")
	}
	if !errors.Is(err, ErrAttestationFailed) {
		t.Errorf("error should wrap ErrAttestationFailed, got %v", err)
	}
	if out.Verified {
		t.Error("outcome must not claim verification")
	}
}

func TestPermissiveAdmitsButDoesNotClaimVerified(t *testing.T) {
	g := &AttestationGate{
		Mode:         AttestationPermissive,
		Verifier:     attestation.New(),
		ChallengeFor: challengeOK,
	}
	out, err := g.Verify(context.Background(), "install-1", nil)
	if err != nil {
		t.Fatalf("permissive mode must not refuse registration: %v", err)
	}
	// The important half: admitting the device is not the same as saying
	// it attested. A caller that reads only the error would wrongly mark
	// this device attested.
	if out.Verified {
		t.Error("permissive admission must still report Verified=false")
	}
	if out.Reason == "" {
		t.Error("a failed check must record why, for the rollout logs")
	}
}

func TestOffSkipsEntirely(t *testing.T) {
	g := &AttestationGate{Mode: AttestationOff}
	out, err := g.Verify(context.Background(), "install-1", nil)
	if err != nil {
		t.Fatalf("off mode must never refuse: %v", err)
	}
	if out.Verified {
		t.Error("off mode must not claim the device was verified")
	}
}

// A deployment that asks for enforcement but wires no verifier is an
// operator error. Admitting everything would silently give them the
// opposite of what they configured.
func TestEnforceWithoutVerifierFailsClosed(t *testing.T) {
	g := &AttestationGate{Mode: AttestationEnforce}
	if _, err := g.Verify(context.Background(), "install-1", []byte("chain")); err == nil {
		t.Fatal("enforce with no verifier must fail closed")
	}
}

func TestPermissiveWithoutVerifierAdmits(t *testing.T) {
	g := &AttestationGate{Mode: AttestationPermissive}
	if _, err := g.Verify(context.Background(), "install-1", []byte("chain")); err != nil {
		t.Fatalf("permissive with no verifier should admit: %v", err)
	}
}

// Replay protection depends on a per-registration challenge. A chain with
// no matching outstanding nonce proves the device attested at some point,
// not that it is attesting now.
func TestMissingChallengeIsRefusedUnderEnforce(t *testing.T) {
	g := &AttestationGate{
		Mode:         AttestationEnforce,
		Verifier:     attestation.New(),
		ChallengeFor: challengeMissing,
	}
	out, err := g.Verify(context.Background(), "install-1", []byte("-----BEGIN CERTIFICATE-----"))
	if err == nil {
		t.Fatal("a chain with no outstanding challenge must be refused")
	}
	if out.Verified {
		t.Error("outcome must not claim verification")
	}
}

// An empty (but non-error) challenge is the same problem: nothing binds
// the chain to this attempt.
func TestEmptyChallengeIsRefusedUnderEnforce(t *testing.T) {
	g := &AttestationGate{
		Mode:     AttestationEnforce,
		Verifier: attestation.New(),
		ChallengeFor: func(_ context.Context, _ string) ([]byte, error) {
			return []byte{}, nil
		},
	}
	if _, err := g.Verify(context.Background(), "i", []byte("chain")); err == nil {
		t.Fatal("an empty challenge must not be accepted as freshness proof")
	}
}

// A garbage chain must be refused rather than parsed loosely.
func TestGarbageChainIsRefused(t *testing.T) {
	g := &AttestationGate{
		Mode:         AttestationEnforce,
		Verifier:     attestation.New(),
		ChallengeFor: challengeOK,
	}
	if _, err := g.Verify(context.Background(), "i", []byte("x")); err == nil {
		t.Fatal(`the literal string "x" must not enrol a device — that was the old behaviour`)
	}
}

func TestModeConstantsAreStable(t *testing.T) {
	// These land in config files and deployment manifests; renaming one
	// silently turns enforcement off.
	if AttestationOff != "off" || AttestationPermissive != "permissive" ||
		AttestationEnforce != "enforce" {
		t.Fatal("attestation mode wire values changed")
	}
}
