package devices

import (
	"context"
	"errors"
	"testing"

	"github.com/aidotvpn/server/internal/domain"
	"github.com/aidotvpn/server/internal/playintegrity"
)

func payloadDecoder(p *playintegrity.TokenPayload) playintegrity.Decoder {
	return func(context.Context, string) (*playintegrity.TokenPayload, error) {
		return p, nil
	}
}

func goodPayload(nonce string) *playintegrity.TokenPayload {
	p := &playintegrity.TokenPayload{}
	p.RequestDetails.RequestPackageName = "com.hospital.emr"
	p.RequestDetails.Nonce = nonce
	p.AppIntegrity.AppRecognitionVerdict = "PLAY_RECOGNIZED"
	p.AppIntegrity.PackageName = "com.hospital.emr"
	p.DeviceIntegrity.DeviceRecognitionVerdict = []string{"MEETS_DEVICE_INTEGRITY"}
	return p
}

func gateWith(t *testing.T, mode PlayIntegrityMode, p *playintegrity.TokenPayload) *PlayIntegrityGate {
	t.Helper()
	v, err := playintegrity.New(playintegrity.Config{
		Decoder:             payloadDecoder(p),
		ExpectedPackageName: "com.hospital.emr",
	})
	if err != nil {
		t.Fatalf("verifier: %v", err)
	}
	return &PlayIntegrityGate{
		Mode:     mode,
		Verifier: v,
		NonceFor: func(context.Context, domain.ID, domain.ID) (string, error) {
			return "the-nonce", nil
		},
	}
}

func TestPlayIntegrityOffIsANoOp(t *testing.T) {
	g := &PlayIntegrityGate{Mode: PlayIntegrityOff}
	out, err := g.Evaluate(context.Background(), domain.ID{}, domain.ID{}, "")
	if err != nil {
		t.Fatalf("off mode must never refuse: %v", err)
	}
	if out.Evaluated {
		t.Error("off mode must not claim it evaluated anything")
	}
}

// A nil gate is the common case for deployments that never configure Play
// Integrity. It must not panic on the registration hot path.
func TestNilGateIsSafe(t *testing.T) {
	var g *PlayIntegrityGate
	if _, err := g.Evaluate(context.Background(), domain.ID{}, domain.ID{}, "tok"); err != nil {
		t.Fatalf("nil gate should be inert: %v", err)
	}
}

func TestPlayIntegrityEnforceRejectsMissingToken(t *testing.T) {
	g := gateWith(t, PlayIntegrityEnforce, goodPayload("the-nonce"))
	if _, err := g.Evaluate(context.Background(), domain.ID{}, domain.ID{}, ""); err == nil {
		t.Fatal("enforce must refuse a registration with no integrity token")
	}
}

func TestPlayIntegrityPermissiveAdmitsButRecordsFailure(t *testing.T) {
	g := gateWith(t, PlayIntegrityPermissive, goodPayload("the-nonce"))
	out, err := g.Evaluate(context.Background(), domain.ID{}, domain.ID{}, "")
	if err != nil {
		t.Fatalf("permissive must not refuse: %v", err)
	}
	if out.Verdict != string(playintegrity.VerdictFail) {
		t.Errorf("verdict = %q, want fail — admitting is not the same as passing", out.Verdict)
	}
}

// The nonce binds this token to the live registration. A token minted
// against a different challenge proves the app was healthy at some point,
// not that it is now.
func TestNonceMismatchFailsUnderEnforce(t *testing.T) {
	g := gateWith(t, PlayIntegrityEnforce, goodPayload("a-different-nonce"))
	_, err := g.Evaluate(context.Background(), domain.ID{}, domain.ID{}, "tok")
	if err == nil {
		t.Fatal("a replayed token must be refused")
	}
	if !errors.Is(err, ErrAttestationFailed) {
		t.Errorf("error should wrap ErrAttestationFailed: %v", err)
	}
}

func TestGoodTokenPasses(t *testing.T) {
	g := gateWith(t, PlayIntegrityEnforce, goodPayload("the-nonce"))
	out, err := g.Evaluate(context.Background(), domain.ID{}, domain.ID{}, "tok")
	if err != nil {
		t.Fatalf("a healthy token must pass: %v", err)
	}
	if !out.Evaluated || out.Verdict != string(playintegrity.VerdictOK) {
		t.Errorf("outcome = %+v", out)
	}
}

// A rooted device produces a genuine-looking token that reports only
// basic integrity. That is exactly what the device-integrity floor exists
// to catch.
func TestBasicIntegrityOnlyIsRefused(t *testing.T) {
	p := goodPayload("the-nonce")
	p.DeviceIntegrity.DeviceRecognitionVerdict = []string{"MEETS_BASIC_INTEGRITY"}
	g := gateWith(t, PlayIntegrityEnforce, p)
	if _, err := g.Evaluate(context.Background(), domain.ID{}, domain.ID{}, "tok"); err == nil {
		t.Fatal("basic-integrity-only device must not pass the default floor")
	}
}

// A sideloaded hospital build is UNRECOGNIZED_VERSION by definition.
// With AllowSideloaded it is a warning, and a warning must not refuse
// enrolment unless the operator asked for that.
func TestSideloadedWarningAdmittedByDefault(t *testing.T) {
	p := goodPayload("the-nonce")
	p.AppIntegrity.AppRecognitionVerdict = "UNRECOGNIZED_VERSION"
	v, err := playintegrity.New(playintegrity.Config{
		Decoder:             payloadDecoder(p),
		ExpectedPackageName: "com.hospital.emr",
		AllowSideloaded:     true,
	})
	if err != nil {
		t.Fatal(err)
	}
	g := &PlayIntegrityGate{
		Mode: PlayIntegrityEnforce, Verifier: v,
		NonceFor: func(context.Context, domain.ID, domain.ID) (string, error) {
			return "the-nonce", nil
		},
	}
	out, err := g.Evaluate(context.Background(), domain.ID{}, domain.ID{}, "tok")
	if err != nil {
		t.Fatalf("a sideloaded build must enrol by default: %v", err)
	}
	if out.Verdict != string(playintegrity.VerdictWarning) {
		t.Errorf("verdict = %q, want warning", out.Verdict)
	}

	// ...unless the operator opts into the strict reading.
	g.TreatWarningAsFailure = true
	if _, err := g.Evaluate(context.Background(), domain.ID{}, domain.ID{}, "tok"); err == nil {
		t.Fatal("TreatWarningAsFailure must make the same token refuse")
	}
}

func TestPlayIntegrityEnforceWithoutVerifierFailsClosed(t *testing.T) {
	g := &PlayIntegrityGate{Mode: PlayIntegrityEnforce}
	if _, err := g.Evaluate(context.Background(), domain.ID{}, domain.ID{}, "tok"); err == nil {
		t.Fatal("enforce with no verifier must fail closed")
	}
}

func TestFingerprintBytes(t *testing.T) {
	full := "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"
	got, ok := fingerprintBytes(full).([]byte)
	if !ok || len(got) != 32 {
		t.Fatalf("full fingerprint should decode to 32 bytes, got %T", fingerprintBytes(full))
	}
	// The gate logs a truncated fingerprint; storing the truncation would
	// make the column useless for lookups, so short values become NULL.
	if fingerprintBytes("aabbccdd") != nil {
		t.Error("a truncated fingerprint must store as NULL, not as a partial")
	}
	if fingerprintBytes("zz"+full[2:]) != nil {
		t.Error("non-hex input must store as NULL")
	}
}
