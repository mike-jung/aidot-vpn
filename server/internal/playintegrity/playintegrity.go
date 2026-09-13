// Package playintegrity verifies Google Play Integrity API tokens.
//
// Phase 7 ships the verification surface and the verdict policy. Actual
// Google Play API call (decrypting the token via the per-app encryption
// key) is left as a single function call — operators wire this up by
// providing their Play Integrity API service-account credentials at
// controller startup.
//
// What we evaluate:
//
//   - appRecognitionVerdict — must be PLAY_RECOGNIZED in production
//     (UNRECOGNIZED_VERSION acceptable in dev / when sideloading).
//
//   - deviceIntegrity — minimum bar configurable per tenant:
//     MEETS_BASIC_INTEGRITY  (lenient — allows custom ROMs)
//     MEETS_DEVICE_INTEGRITY (default — requires Play Protect cert)
//     MEETS_STRONG_INTEGRITY (strict — also requires recent OS patch)
//
//   - appLicensingVerdict — recommended but not required by AidotVpn.
//
//   - Nonce match — the integrity token is bound to the same attestation
//     challenge we issued for the Key Attestation flow. This double-binds
//     the same nonce to both gates so an attacker can't replay either
//     in isolation.
package playintegrity

import (
	"context"
	"errors"
	"fmt"
)

// Verdict is the high-level outcome our Register flow consumes.
type Verdict string

const (
	VerdictOK      Verdict = "ok"
	VerdictWarning Verdict = "warning"
	VerdictFail    Verdict = "fail"
)

// MinDeviceIntegrity controls how strict the device-class check is.
type MinDeviceIntegrity int

const (
	IntegrityBasic  MinDeviceIntegrity = 1
	IntegrityDevice MinDeviceIntegrity = 2
	IntegrityStrong MinDeviceIntegrity = 3
)

// TokenPayload mirrors the JSON shape Google's Play Integrity decryption
// returns. We only declare fields we use; unknown fields are ignored.
type TokenPayload struct {
	RequestDetails struct {
		RequestPackageName string `json:"requestPackageName"`
		Nonce              string `json:"nonce"`
		Timestamp          int64  `json:"timestampMillis"`
	} `json:"requestDetails"`
	AppIntegrity struct {
		AppRecognitionVerdict string `json:"appRecognitionVerdict"`
		PackageName           string `json:"packageName"`
	} `json:"appIntegrity"`
	DeviceIntegrity struct {
		DeviceRecognitionVerdict []string `json:"deviceRecognitionVerdict"`
	} `json:"deviceIntegrity"`
	AccountDetails struct {
		AppLicensingVerdict string `json:"appLicensingVerdict"`
	} `json:"accountDetails"`
}

// Decoder is the function the controller plugs in at startup. In
// production it makes the Google Play Integrity REST call:
//
//	POST https://playintegrity.googleapis.com/v1/{packageName}:decodeIntegrityToken
//
// In dev / staging operators can wire up a stub that decrypts the token
// against locally-managed encryption keys, or one that does no decryption
// and simply rejects all tokens.
type Decoder func(ctx context.Context, token string) (*TokenPayload, error)

// Config configures Play Integrity verification.
type Config struct {
	// Decoder retrieves the verdict payload from a token. Required.
	Decoder Decoder

	// ExpectedPackageName guards against tokens minted for a different
	// app sharing the same Play Integrity setup. Required.
	ExpectedPackageName string

	// MinDeviceIntegrity sets the floor for the deviceIntegrity check.
	// Default IntegrityDevice.
	MinDeviceIntegrity MinDeviceIntegrity

	// AllowSideloaded controls whether UNRECOGNIZED_VERSION is treated
	// as a warning (true) or failure (false). Defaults to false.
	AllowSideloaded bool
}

// Verifier wraps a Config + Decoder.
type Verifier struct {
	cfg Config
}

func New(cfg Config) (*Verifier, error) {
	if cfg.Decoder == nil {
		return nil, errors.New("playintegrity.New: Decoder is required")
	}
	if cfg.ExpectedPackageName == "" {
		return nil, errors.New("playintegrity.New: ExpectedPackageName is required")
	}
	if cfg.MinDeviceIntegrity == 0 {
		cfg.MinDeviceIntegrity = IntegrityDevice
	}
	return &Verifier{cfg: cfg}, nil
}

// VerifyResult is what Verify returns on success.
type VerifyResult struct {
	Verdict               Verdict
	Reasons               []string // human-readable issues that produced Warning / Fail
	DeviceIntegrityLabels []string
	PackageName           string
}

// Verify runs the verdict policy. expectedNonce is the same attestation
// challenge issued elsewhere — see allowlist.IssueChallenge.
func (v *Verifier) Verify(ctx context.Context, token string, expectedNonce string) (*VerifyResult, error) {
	payload, err := v.cfg.Decoder(ctx, token)
	if err != nil {
		return nil, fmt.Errorf("decode token: %w", err)
	}
	res := &VerifyResult{
		Verdict:               VerdictOK,
		PackageName:           payload.AppIntegrity.PackageName,
		DeviceIntegrityLabels: payload.DeviceIntegrity.DeviceRecognitionVerdict,
	}

	if payload.RequestDetails.RequestPackageName != v.cfg.ExpectedPackageName {
		res.Verdict = VerdictFail
		res.Reasons = append(res.Reasons,
			fmt.Sprintf("requestPackageName=%q, expected %q",
				payload.RequestDetails.RequestPackageName, v.cfg.ExpectedPackageName))
	}

	if payload.RequestDetails.Nonce != expectedNonce {
		res.Verdict = VerdictFail
		res.Reasons = append(res.Reasons, "nonce mismatch (replay protection)")
	}

	switch payload.AppIntegrity.AppRecognitionVerdict {
	case "PLAY_RECOGNIZED":
		// good
	case "UNRECOGNIZED_VERSION":
		if v.cfg.AllowSideloaded {
			res.demoteTo(VerdictWarning)
			res.Reasons = append(res.Reasons, "UNRECOGNIZED_VERSION (allowed)")
		} else {
			res.Verdict = VerdictFail
			res.Reasons = append(res.Reasons, "UNRECOGNIZED_VERSION not allowed")
		}
	case "UNEVALUATED", "":
		res.demoteTo(VerdictWarning)
		res.Reasons = append(res.Reasons, "appRecognitionVerdict missing or unevaluated")
	default:
		res.Verdict = VerdictFail
		res.Reasons = append(res.Reasons, "unrecognised appRecognitionVerdict: "+payload.AppIntegrity.AppRecognitionVerdict)
	}

	if !meetsDeviceIntegrity(payload.DeviceIntegrity.DeviceRecognitionVerdict, v.cfg.MinDeviceIntegrity) {
		res.Verdict = VerdictFail
		res.Reasons = append(res.Reasons, fmt.Sprintf(
			"deviceIntegrity %v below required level %d",
			payload.DeviceIntegrity.DeviceRecognitionVerdict, v.cfg.MinDeviceIntegrity))
	}

	return res, nil
}

// demoteTo lowers the verdict only — never raises it back to OK.
func (r *VerifyResult) demoteTo(v Verdict) {
	if r.Verdict == VerdictOK {
		r.Verdict = v
	}
}

func meetsDeviceIntegrity(labels []string, min MinDeviceIntegrity) bool {
	rank := func(label string) MinDeviceIntegrity {
		switch label {
		case "MEETS_STRONG_INTEGRITY":
			return IntegrityStrong
		case "MEETS_DEVICE_INTEGRITY":
			return IntegrityDevice
		case "MEETS_BASIC_INTEGRITY":
			return IntegrityBasic
		default:
			return 0
		}
	}
	var best MinDeviceIntegrity
	for _, l := range labels {
		if r := rank(l); r > best {
			best = r
		}
	}
	return best >= min
}
