package devices

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/aidotvpn/server/internal/domain"
	"github.com/aidotvpn/server/internal/playintegrity"
)

// Play Integrity, wired in 0.18.0.
//
// It answers a different question from key attestation, and the two are
// complementary rather than redundant:
//
//	Key attestation  "was this key generated inside genuine TEE on a
//	                  device whose root Google provisioned?"  — hardware,
//	                  durable, provable long after the fact.
//
//	Play Integrity   "is this app install, on this device, trustworthy
//	                  right now?" — software signals, current, catches
//	                  a repackaged APK that a hardware-attested handset
//	                  would happily produce a valid chain for.
//
// A device can pass hardware attestation and fail Play Integrity: the
// phone is genuine and unmodified, but the app talking to us is not the
// one we published. That is precisely the case ExpectedPackages in the
// attestation gate cannot fully close on its own, because the attested
// package name proves which app requested the key, not that the app's
// code is unmodified.
//
// Both gates are bound to the SAME nonce (allowlist.IssueChallenge), so
// neither can be replayed in isolation.

// PlayIntegrityMode mirrors AttestationMode: off, permissive, enforce.
type PlayIntegrityMode string

const (
	PlayIntegrityOff        PlayIntegrityMode = "off"
	PlayIntegrityPermissive PlayIntegrityMode = "permissive"
	PlayIntegrityEnforce    PlayIntegrityMode = "enforce"
)

// PlayIntegrityGate evaluates an integrity token at registration.
type PlayIntegrityGate struct {
	Mode     PlayIntegrityMode
	Verifier *playintegrity.Verifier
	Logger   interface {
		Info(string, ...any)
		Warn(string, ...any)
		Error(string, ...any)
	}

	// NonceFor returns the challenge this controller issued, hex- or
	// base64-encoded exactly as the client was told to embed it.
	NonceFor func(ctx context.Context, tenantID, userID domain.ID) (string, error)

	// TreatWarningAsFailure decides what `warning` means under enforce.
	//
	// Default false. A warning is usually UNRECOGNIZED_VERSION or an
	// unevaluated verdict — states a legitimately-sideloaded hospital
	// build produces routinely. Refusing those by default would make the
	// gate unusable for exactly the deployment this product targets, so
	// the strict reading is opt-in.
	TreatWarningAsFailure bool
}

// PlayIntegrityOutcome records what happened, for audit and logging.
type PlayIntegrityOutcome struct {
	Evaluated bool
	Verdict   string
	Reasons   []string
	Labels    []string
	Package   string
}

// Evaluate runs the gate.
//
// Returns (outcome, error). A non-nil error means enrolment is refused;
// an outcome with a non-ok verdict and a nil error means the check failed
// but the mode admits the device anyway. As with the attestation gate,
// callers must not read "no error" as "passed".
func (g *PlayIntegrityGate) Evaluate(
	ctx context.Context,
	tenantID, userID domain.ID,
	token string,
) (PlayIntegrityOutcome, error) {
	out := PlayIntegrityOutcome{}

	if g == nil || g.Mode == "" || g.Mode == PlayIntegrityOff {
		return out, nil
	}
	if g.Verifier == nil {
		if g.Mode == PlayIntegrityEnforce {
			return out, fmt.Errorf(
				"%w: play integrity is set to enforce but no verifier is configured",
				ErrAttestationFailed)
		}
		return out, nil
	}

	if strings.TrimSpace(token) == "" {
		out.Verdict = string(playintegrity.VerdictFail)
		out.Reasons = []string{"device sent no integrity token"}
		return out, g.decide(out)
	}

	nonce := ""
	if g.NonceFor != nil {
		n, err := g.NonceFor(ctx, tenantID, userID)
		if err != nil {
			out.Verdict = string(playintegrity.VerdictFail)
			out.Reasons = []string{"no outstanding challenge: " + err.Error()}
			return out, g.decide(out)
		}
		nonce = n
	}

	res, err := g.Verifier.Verify(ctx, token, nonce)
	if err != nil {
		// A decode failure is usually Google being unreachable or a
		// credentials problem, not a bad device. Under enforce that still
		// blocks enrolment — the alternative is that an outage silently
		// disables the gate — but the reason says which it was.
		out.Verdict = string(playintegrity.VerdictFail)
		out.Reasons = []string{"token decode failed: " + err.Error()}
		return out, g.decide(out)
	}

	out.Evaluated = true
	out.Verdict = string(res.Verdict)
	out.Reasons = res.Reasons
	out.Labels = res.DeviceIntegrityLabels
	out.Package = res.PackageName

	if res.Verdict == playintegrity.VerdictOK {
		if g.Logger != nil {
			g.Logger.Info("play integrity passed",
				"package", out.Package, "labels", strings.Join(out.Labels, ","))
		}
		return out, nil
	}
	return out, g.decide(out)
}

func (g *PlayIntegrityGate) decide(out PlayIntegrityOutcome) error {
	failing := out.Verdict == string(playintegrity.VerdictFail) ||
		(out.Verdict == string(playintegrity.VerdictWarning) && g.TreatWarningAsFailure)

	if g.Logger != nil {
		msg := "play integrity check did not pass"
		fields := []any{
			"mode", string(g.Mode),
			"verdict", out.Verdict,
			"reasons", strings.Join(out.Reasons, "; "),
		}
		if failing && g.Mode == PlayIntegrityEnforce {
			g.Logger.Error(msg, fields...)
		} else {
			g.Logger.Warn(msg, fields...)
		}
	}

	if g.Mode == PlayIntegrityEnforce && failing {
		return fmt.Errorf("%w: play integrity %s (%s)",
			ErrAttestationFailed, out.Verdict, strings.Join(out.Reasons, "; "))
	}
	return nil
}

// SetPlayIntegrityGate installs the gate. Called from the controller's
// wiring, alongside SetAttestationGate.
func (s *Service) SetPlayIntegrityGate(g *PlayIntegrityGate) { s.playIntegrity = g }

// runPlayIntegrity applies the gate during Register.
func (s *Service) runPlayIntegrity(ctx context.Context, p RegisterParams) (PlayIntegrityOutcome, error) {
	if s.playIntegrity == nil {
		return PlayIntegrityOutcome{}, nil
	}
	return s.playIntegrity.Evaluate(ctx, p.TenantID, p.UserID, p.AttestationToken)
}

// recordAttestation writes an attestation_records row.
//
// Wires three columns that existed since 0001/0002 and were never
// written: cert_fingerprint, play_integrity_verdict and security_level.
// Without this the table recorded that *something* was evaluated but not
// what the evidence actually said — which is the whole point of keeping
// an attestation history.
//
// Best-effort by design: a failure to record must not block a
// registration that otherwise passed. An admin losing one audit row is a
// smaller harm than a clinician unable to enrol.
func (s *Service) recordAttestation(
	ctx context.Context,
	q executor,
	deviceID domain.ID,
	att AttestationOutcome,
	pi PlayIntegrityOutcome,
) {
	source := "none"
	if pi.Evaluated {
		source = "play_integrity"
	}

	verdict := "ok"
	switch {
	case att.Mode != "" && att.Mode != AttestationOff && !att.Verified:
		verdict = "fail"
	case pi.Verdict == string(playintegrity.VerdictFail):
		verdict = "fail"
	case pi.Verdict == string(playintegrity.VerdictWarning) || att.Reason != "":
		verdict = "warning"
	}

	notes := strings.Join(append(append([]string{}, att.Reason), pi.Reasons...), "; ")
	notes = strings.Trim(strings.TrimSpace(notes), ";")
	if len(notes) > 2000 {
		notes = notes[:2000]
	}

	payload, err := json.Marshal(map[string]any{
		"attestation": map[string]any{
			"mode":           string(att.Mode),
			"verified":       att.Verified,
			"security_level": att.SecurityLevel,
			"boot_state":     att.BootState,
			"device_locked":  att.DeviceLocked,
			"package":        att.Package,
		},
		"play_integrity": map[string]any{
			"evaluated": pi.Evaluated,
			"verdict":   pi.Verdict,
			"labels":    pi.Labels,
			"package":   pi.Package,
		},
	})
	if err != nil {
		payload = nil
	}

	_, err = q.ExecContext(ctx, `
		INSERT INTO attestation_records
		  (id, device_id, source, verdict, payload, notes,
		   cert_fingerprint, play_integrity_verdict, security_level)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		domain.NewID().Bytes(), deviceID.Bytes(), source, verdict,
		nullIfEmptyBytes(payload), nullIfEmpty(notes),
		fingerprintBytes(att.Fingerprint),
		nullIfEmpty(pi.Verdict), nullIfEmpty(att.SecurityLevel))
	if err != nil && s.attestation != nil && s.attestation.Logger != nil {
		s.attestation.Logger.Warn("failed to record attestation",
			"device", deviceID.String(), "err", err.Error())
	}
}

// fingerprintBytes decodes the short hex fingerprint the gate reports
// back into bytes for BINARY(32) storage, or NULL when absent.
//
// The gate logs a truncated fingerprint for readability; storing the
// truncation would make the column useless for lookups, so a short value
// is stored as NULL rather than as a misleading partial.
func fingerprintBytes(hexFP string) any {
	const fullHexLen = 64
	if len(hexFP) != fullHexLen {
		return nil
	}
	out := make([]byte, 32)
	for i := 0; i < 32; i++ {
		var b byte
		for j := 0; j < 2; j++ {
			c := hexFP[i*2+j]
			var v byte
			switch {
			case c >= '0' && c <= '9':
				v = c - '0'
			case c >= 'a' && c <= 'f':
				v = c - 'a' + 10
			case c >= 'A' && c <= 'F':
				v = c - 'A' + 10
			default:
				return nil
			}
			b = b<<4 | v
		}
		out[i] = b
	}
	return out
}

func nullIfEmptyBytes(b []byte) any {
	if len(b) == 0 {
		return nil
	}
	return string(b)
}

var _ = sql.ErrNoRows
