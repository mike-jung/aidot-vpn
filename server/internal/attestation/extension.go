package attestation

import (
	"encoding/asn1"
	"errors"
)

// Extension holds the subset of Android Key Attestation extension fields
// AidotVpn actually uses. The full schema has dozens of fields covering
// Keymaster-internal policies; documentation lives at
// https://source.android.com/docs/security/features/keystore/attestation.
type Extension struct {
	AttestationVersion       int
	AttestationSecurityLevel int
	KeymasterVersion         int
	KeymasterSecurityLevel   int
	AttestationChallenge     []byte
	UniqueId                 []byte
	AttestedPackageName      string
	AttestedPackageSignature []byte

	// RootOfTrust carries the device's boot state (0.13.0). Nil when the
	// attestation omits it, which by itself is grounds for suspicion on a
	// modern device — every Keymaster 2+ implementation emits one.
	RootOfTrust *RootOfTrust
}

// VerifiedBootState is the device's verified-boot verdict.
type VerifiedBootState int

const (
	// BootVerified — full chain of trust from the OEM-provisioned root.
	// The only state a stock, unmodified device reports.
	BootVerified VerifiedBootState = 0
	// BootSelfSigned — bootloader unlocked and the boot image is signed
	// by a user-supplied key. Custom ROM territory.
	BootSelfSigned VerifiedBootState = 1
	// BootUnverified — bootloader unlocked, no verification performed.
	BootUnverified VerifiedBootState = 2
	// BootFailed — verification ran and failed.
	BootFailed VerifiedBootState = 3
)

func (v VerifiedBootState) String() string {
	switch v {
	case BootVerified:
		return "verified"
	case BootSelfSigned:
		return "self_signed"
	case BootUnverified:
		return "unverified"
	case BootFailed:
		return "failed"
	default:
		return "unknown"
	}
}

// RootOfTrust is the boot-state block from the TEE-enforced
// AuthorizationList.
//
// This is what distinguishes a stock handset from a rooted one. Without
// it, key attestation answers only "was this key made in real TEE?" — and
// a rooted device still has real TEE. Hardware attestation on a device
// with an unlocked bootloader is genuine attestation of an untrustworthy
// device, which is exactly the case a hospital needs to exclude.
type RootOfTrust struct {
	VerifiedBootKey   []byte
	DeviceLocked      bool
	VerifiedBootState VerifiedBootState
	VerifiedBootHash  []byte
}

// parseExtension parses an OID 1.3.6.1.4.1.11129.2.1.17 OCTET STRING
// payload into [Extension].
//
// The on-the-wire structure is roughly:
//
//	KeyDescription ::= SEQUENCE {
//	    attestationVersion         INTEGER,
//	    attestationSecurityLevel   ENUMERATED,
//	    keymasterVersion           INTEGER,
//	    keymasterSecurityLevel     ENUMERATED,
//	    attestationChallenge       OCTET_STRING,
//	    uniqueId                   OCTET_STRING,
//	    softwareEnforced           AuthorizationList,
//	    teeEnforced                AuthorizationList
//	}
//
//	AuthorizationList ::= SEQUENCE {
//	    ...
//	    attestationApplicationId  [709] EXPLICIT OCTET_STRING OPTIONAL,
//	    ...
//	}
//
// We unmarshal the outer fields and then surface attestation-application-id
// from the TEE-enforced AuthorizationList when present. We deliberately
// don't parse every authorization (root-of-trust, OS version, patch level,
// purposes, etc.) because the AidotVpn allowlist doesn't gate on those
// today — when we add a "minimum OS patch" policy in Phase 7+, we'll
// extend this parser.
func parseExtension(raw []byte) (*Extension, error) {
	var outer struct {
		AttestationVersion       int
		AttestationSecurityLevel asn1.Enumerated
		KeymasterVersion         int
		KeymasterSecurityLevel   asn1.Enumerated
		AttestationChallenge     []byte
		UniqueId                 []byte
		SoftwareEnforced         asn1.RawValue
		TeeEnforced              asn1.RawValue
	}
	if rest, err := asn1.Unmarshal(raw, &outer); err != nil {
		return nil, err
	} else if len(rest) > 0 {
		// Trailing data is suspect; AOSP's parser tolerates it but we
		// stay strict.
		return nil, errors.New("trailing data after KeyDescription")
	}

	ext := &Extension{
		AttestationVersion:       outer.AttestationVersion,
		AttestationSecurityLevel: int(outer.AttestationSecurityLevel),
		KeymasterVersion:         outer.KeymasterVersion,
		KeymasterSecurityLevel:   int(outer.KeymasterSecurityLevel),
		AttestationChallenge:     outer.AttestationChallenge,
		UniqueId:                 outer.UniqueId,
	}

	// Optional: peek inside teeEnforced for attestationApplicationId. The
	// AuthorizationList is a SEQUENCE with all-optional context-tagged
	// fields. We scan looking for tag [709] which is OCTET_STRING-wrapped
	// attestationApplicationId.
	if pkg := scanAttestedAppId(outer.TeeEnforced.Bytes); pkg != "" {
		ext.AttestedPackageName = pkg
	} else if pkg := scanAttestedAppId(outer.SoftwareEnforced.Bytes); pkg != "" {
		ext.AttestedPackageName = pkg
	}

	// RootOfTrust is read ONLY from the TEE-enforced list. The
	// software-enforced list is, by definition, whatever the (possibly
	// compromised) OS chose to claim — accepting a boot state from there
	// would let a rooted device simply assert that it is verified.
	ext.RootOfTrust = scanRootOfTrust(outer.TeeEnforced.Bytes)

	return ext, nil
}

// rootOfTrustTag is the context-specific tag of RootOfTrust inside an
// AuthorizationList.
const rootOfTrustTag = 704

// scanRootOfTrust extracts the [704] EXPLICIT RootOfTrust block.
//
//	RootOfTrust ::= SEQUENCE {
//	    verifiedBootKey    OCTET_STRING,
//	    deviceLocked       BOOLEAN,
//	    verifiedBootState  ENUMERATED,
//	    verifiedBootHash   OCTET_STRING  -- KeyMint v3+; absent on older
//	}
//
// Returns nil when absent or malformed. Callers must treat nil as "no
// boot evidence", never as "boot is fine".
func scanRootOfTrust(seqBody []byte) *RootOfTrust {
	rest := seqBody
	for len(rest) > 0 {
		var rv asn1.RawValue
		next, err := asn1.Unmarshal(rest, &rv)
		if err != nil {
			return nil
		}
		if rv.Class == asn1.ClassContextSpecific && rv.Tag == rootOfTrustTag {
			// EXPLICIT tagging: the body holds the RootOfTrust SEQUENCE.
			var inner asn1.RawValue
			if _, err := asn1.Unmarshal(rv.Bytes, &inner); err != nil {
				return nil
			}
			return parseRootOfTrust(inner.Bytes)
		}
		rest = next
	}
	return nil
}

func parseRootOfTrust(body []byte) *RootOfTrust {
	// verifiedBootHash is absent on Keymaster < 3, so the struct is
	// parsed field by field rather than with a fixed-shape unmarshal —
	// a fixed shape would reject every older device outright.
	rot := &RootOfTrust{}

	var key []byte
	rest, err := asn1.Unmarshal(body, &key)
	if err != nil {
		return nil
	}
	rot.VerifiedBootKey = key

	var locked bool
	rest, err = asn1.Unmarshal(rest, &locked)
	if err != nil {
		return nil
	}
	rot.DeviceLocked = locked

	var state asn1.Enumerated
	rest, err = asn1.Unmarshal(rest, &state)
	if err != nil {
		return nil
	}
	rot.VerifiedBootState = VerifiedBootState(state)

	// Optional trailing hash.
	if len(rest) > 0 {
		var hash []byte
		if _, err := asn1.Unmarshal(rest, &hash); err == nil {
			rot.VerifiedBootHash = hash
		}
	}
	return rot
}

// scanAttestedAppId walks an AuthorizationList SEQUENCE body looking for
// the [709] EXPLICIT OCTET_STRING field. Returns the first package name
// inside it, or "" if not found.
//
// The AuthorizationList is a SEQUENCE OF context-tagged elements. We
// linear-scan because the tag numbers are non-sequential and very high
// (up to 720+); a full struct unmarshal would be brittle.
func scanAttestedAppId(seqBody []byte) string {
	rest := seqBody
	for len(rest) > 0 {
		var rv asn1.RawValue
		next, err := asn1.Unmarshal(rest, &rv)
		if err != nil {
			return ""
		}
		// Tag 709 in context-specific class (high tag form).
		if rv.Class == asn1.ClassContextSpecific && rv.Tag == 709 {
			// The body is an OCTET STRING containing a DER-encoded
			// AttestationApplicationId structure:
			//   SEQUENCE { packageInfos SET OF PackageInfo, signatureDigests SET OF OCTET_STRING }
			//   PackageInfo ::= SEQUENCE { packageName OCTET_STRING, version INTEGER }
			var inner asn1.RawValue
			if _, err := asn1.Unmarshal(rv.Bytes, &inner); err == nil {
				if pkg := firstPackageName(inner.Bytes); pkg != "" {
					return pkg
				}
			}
		}
		rest = next
	}
	return ""
}

func firstPackageName(appIdBody []byte) string {
	// appIdBody is the AttestationApplicationId SEQUENCE. First field is
	// packageInfos (SET OF SEQUENCE).
	var packageInfosWrap asn1.RawValue
	if _, err := asn1.Unmarshal(appIdBody, &packageInfosWrap); err != nil {
		return ""
	}
	rest := packageInfosWrap.Bytes
	for len(rest) > 0 {
		var pkgInfo asn1.RawValue
		next, err := asn1.Unmarshal(rest, &pkgInfo)
		if err != nil {
			return ""
		}
		// pkgInfo is SEQUENCE { packageName OCTET_STRING, version INTEGER }
		var name []byte
		if _, err := asn1.Unmarshal(pkgInfo.Bytes, &name); err == nil && len(name) > 0 {
			return string(name)
		}
		rest = next
	}
	return ""
}
