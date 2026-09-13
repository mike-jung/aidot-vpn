package devices

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/aidotvpn/server/internal/attestation"
	"github.com/aidotvpn/server/internal/domain"
)

// Attestation enforcement, wired in 0.13.0.
//
// What was there before: `Register` set a device to `active` whenever
// `AttestationToken` was any non-empty string, and the HTTP layer decoded
// `attestation_chain_pem` and then threw it away without passing it in.
// So the hardware attestation chain — the actual evidence — never reached
// a verifier, and the literal string "x" was sufficient to enrol.
//
// The verifier itself (internal/attestation) was already written and
// tested. Only the wiring was missing, which is a recurring shape in this
// codebase: the mechanism exists, the last connection doesn't. That is
// worth stating plainly because it is also why the gap survived so long —
// everything *looked* present.

// AttestationMode controls how strictly registration enforces attestation.
type AttestationMode string

const (
	// AttestationOff skips verification entirely. Devices go straight to
	// active. Appropriate only for local development.
	AttestationOff AttestationMode = "off"

	// AttestationPermissive verifies and logs, but admits the device
	// either way. This is the rollout mode: run it for a week, read the
	// logs, find out how many handsets in the fleet would have been
	// refused before you refuse them.
	AttestationPermissive AttestationMode = "permissive"

	// AttestationEnforce refuses registration when verification fails.
	// The device is left in pending_attest and, per the 0.10.0 gateway
	// rules, receives no WireGuard peer at all.
	AttestationEnforce AttestationMode = "enforce"
)

// AttestationGate verifies a device's attestation chain at registration.
type AttestationGate struct {
	Mode     AttestationMode
	Verifier *attestation.Verifier
	Logger   *slog.Logger

	// VerifyAndConsume is the production verification path. It performs
	// challenge lookup, TTL enforcement, chain verification, nonce
	// consumption and (when the tenant requires it) the fingerprint
	// allowlist check — all in one call.
	//
	// This delegates to allowlist.Service rather than reimplementing
	// challenge handling here. Two independent implementations of nonce
	// lifecycle is exactly the kind of duplication that produces a
	// replay hole when only one of them gets a fix.
	//
	// When nil, the gate falls back to ChallengeFor + Verifier below,
	// which is the path the unit tests drive.
	VerifyAndConsume func(
		ctx context.Context,
		tenantID, userID domain.ID,
		chainPEM []byte,
	) (*attestation.Result, error)

	// ChallengeFor returns the nonce this controller issued to the given
	// install. Replay protection depends entirely on this: without a
	// per-registration challenge, an attacker who once captured a valid
	// chain from a genuine device could replay it forever.
	//
	// Only consulted when VerifyAndConsume is nil.
	ChallengeFor func(ctx context.Context, installID string) ([]byte, error)

	// ConsumeChallenge invalidates the nonce after use, so a captured
	// chain cannot be replayed even within the challenge's lifetime.
	ConsumeChallenge func(ctx context.Context, installID string) error

	// ExpectedPackages, when non-empty, requires the attested package
	// name to be one of these. This binds the attestation to *our* app
	// rather than to any app on a genuine device — without it, a
	// malicious app on an otherwise-trustworthy handset produces a chain
	// that verifies.
	ExpectedPackages []string
}

// ErrAttestationFailed is returned when enforcement is on and the chain
// does not verify.
var ErrAttestationFailed = errors.New("device attestation failed")

// AttestationOutcome records what happened, for audit and for the
// device's stored status.
type AttestationOutcome struct {
	Verified      bool
	Mode          AttestationMode
	SecurityLevel string
	BootState     string
	DeviceLocked  bool
	Package       string
	Fingerprint   string
	// Reason is populated when Verified is false.
	Reason string
}

// Verify checks the supplied chain and reports whether the device may
// become active.
//
// The (outcome, error) split matters: a non-nil error means enrolment is
// refused, while an outcome with Verified=false and a nil error means the
// check failed but the mode allows admission anyway. Callers must not
// treat "no error" as "attested".
func (g *AttestationGate) Verify(
	ctx context.Context,
	installID string,
	chainPEM []byte,
) (AttestationOutcome, error) {
	return g.verify(ctx, installID, domain.ID{}, domain.ID{}, chainPEM)
}

// VerifyFor is the tenant/user-scoped entry point used by Register.
func (g *AttestationGate) VerifyFor(
	ctx context.Context,
	installID string,
	tenantID, userID domain.ID,
	chainPEM []byte,
) (AttestationOutcome, error) {
	return g.verify(ctx, installID, tenantID, userID, chainPEM)
}

func (g *AttestationGate) verify(
	ctx context.Context,
	installID string,
	tenantID, userID domain.ID,
	chainPEM []byte,
) (AttestationOutcome, error) {
	out := AttestationOutcome{Mode: g.Mode}

	if g.Mode == "" || g.Mode == AttestationOff {
		out.Reason = "attestation disabled"
		return out, nil
	}

	// Production path: delegate the whole challenge + verify + consume
	// dance to the allowlist service.
	if g.VerifyAndConsume != nil {
		if len(chainPEM) == 0 {
			out.Reason = "device sent no attestation chain"
			return out, g.decide(out)
		}
		res, err := g.VerifyAndConsume(ctx, tenantID, userID, chainPEM)
		if err != nil {
			out.Reason = err.Error()
			return out, g.decide(out)
		}
		return g.fromResult(out, installID, res)
	}

	if g.Verifier == nil {
		// A configured mode with no verifier is a deployment error, not
		// a device problem. Failing closed under enforce is the only
		// safe reading: the operator asked for enforcement and we cannot
		// provide it.
		out.Reason = "no verifier configured"
		if g.Mode == AttestationEnforce {
			return out, fmt.Errorf("%w: attestation is set to enforce but no verifier is configured",
				ErrAttestationFailed)
		}
		return out, nil
	}

	if len(chainPEM) == 0 {
		out.Reason = "device sent no attestation chain"
		return out, g.decide(out)
	}

	challenge, err := g.ChallengeFor(ctx, installID)
	if err != nil {
		out.Reason = "no outstanding challenge for this install: " + err.Error()
		return out, g.decide(out)
	}
	if len(challenge) == 0 {
		// No challenge means we cannot bind this chain to this
		// registration attempt, so the chain proves only that the device
		// once attested — not that it is attesting now.
		out.Reason = "no challenge was issued; cannot prove freshness"
		return out, g.decide(out)
	}

	res, err := g.Verifier.VerifyChain(chainPEM, challenge)
	if err != nil {
		out.Reason = err.Error()
		return out, g.decide(out)
	}

	// Burn the challenge. Done only on success: a failed attempt should
	// not consume a nonce, or a device with a transient problem would
	// need a fresh challenge round-trip for every retry.
	if g.ConsumeChallenge != nil {
		if err := g.ConsumeChallenge(ctx, installID); err != nil && g.Logger != nil {
			// Non-fatal for this registration, but log loudly: a
			// challenge that survives means the window for replay stays
			// open until it expires.
			g.Logger.Warn("failed to consume attestation challenge",
				"install", installID, "err", err.Error())
		}
	}
	return g.fromResult(out, installID, res)
}

// fromResult applies the package check and fills in the outcome.
func (g *AttestationGate) fromResult(
	out AttestationOutcome,
	installID string,
	res *attestation.Result,
) (AttestationOutcome, error) {
	out.SecurityLevel = string(res.SecurityLevel)
	out.Package = res.AttestedPackageName
	out.Fingerprint = fmt.Sprintf("%x", res.Fingerprint[:8])
	if res.RootOfTrust != nil {
		out.BootState = res.RootOfTrust.VerifiedBootState.String()
		out.DeviceLocked = res.RootOfTrust.DeviceLocked
	}

	if len(g.ExpectedPackages) > 0 && !contains(g.ExpectedPackages, res.AttestedPackageName) {
		out.Reason = fmt.Sprintf("attested package %q is not in the expected set",
			res.AttestedPackageName)
		return out, g.decide(out)
	}

	out.Verified = true
	if g.Logger != nil {
		g.Logger.Info("device attestation passed",
			"install", installID,
			"security_level", out.SecurityLevel,
			"boot_state", out.BootState,
			"locked", out.DeviceLocked,
			"package", out.Package,
			"fp", out.Fingerprint)
	}
	return out, nil
}

// decide applies the mode to a failed verification.
func (g *AttestationGate) decide(out AttestationOutcome) error {
	if g.Logger != nil {
		lvl := slog.LevelWarn
		if g.Mode == AttestationEnforce {
			lvl = slog.LevelError
		}
		g.Logger.Log(context.Background(), lvl, "device attestation failed",
			"mode", string(g.Mode), "reason", out.Reason)
	}
	if g.Mode == AttestationEnforce {
		return fmt.Errorf("%w: %s", ErrAttestationFailed, out.Reason)
	}
	return nil
}

func contains(hay []string, needle string) bool {
	for _, h := range hay {
		if h == needle {
			return true
		}
	}
	return false
}

// runAttestation is the Service-side helper that applies the gate.
//
// Returns (true, nil) when the device may be marked active, (false, nil)
// when it may not but registration continues, and a non-nil error when
// enforcement refuses the registration outright.
func (s *Service) runAttestation(ctx context.Context, p RegisterParams) (bool, error) {
	ok, _, err := s.runAttestationWithOutcome(ctx, p)
	return ok, err
}

// runAttestationWithOutcome is runAttestation plus the detail needed for
// the attestation_records row.
func (s *Service) runAttestationWithOutcome(
	ctx context.Context,
	p RegisterParams,
) (bool, AttestationOutcome, error) {
	if s.attestation == nil || s.attestation.Mode == "" || s.attestation.Mode == AttestationOff {
		// Development default. Note this preserves the old behaviour
		// only when explicitly configured off — the controller's config
		// loader defaults to permissive so an unconfigured production
		// deployment gets logs rather than silent acceptance.
		return true, AttestationOutcome{Mode: AttestationOff}, nil
	}
	out, err := s.attestation.VerifyFor(
		ctx, p.InstallID, p.TenantID, p.UserID, p.AttestationChainPEM)
	if err != nil {
		return false, out, err
	}
	if out.Verified {
		return true, out, nil
	}
	// Permissive: admit, but do not claim the device is attested.
	return s.attestation.Mode == AttestationPermissive, out, nil
}
