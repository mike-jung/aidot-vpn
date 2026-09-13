// Package attestation verifies Android Key Attestation cert chains and
// (in Phase 7) Play Integrity tokens.
//
// The two mechanisms answer different but complementary questions:
//
//   - Key Attestation: "did this exact cryptographic key get generated
//     inside genuine TEE/StrongBox on a device whose root was provisioned
//     by Google?"  Returns a stable fingerprint (SHA-256 of the leaf
//     attestation cert's SubjectPublicKeyInfo) — same device, same
//     fingerprint, even after re-installing the AidotVpn app.
//
//   - Play Integrity: "is this app on this device + Play install
//     trustworthy *right now* (per software signals)?"  Returns a verdict
//     enum that summarises code tampering, device class, OS state.
//
// AidotVpn uses Key Attestation for the registered-device allowlist
// (the 디바이스 식별자 + enrolment use case), and Play Integrity as a
// separate gate for "must be a non-rooted certified device" policies.
package attestation

import (
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"time"
)

// ChallengeBytes is the canonical length of an attestation challenge.
// 32 bytes lines up with hash output sizes and gives ~256 bits of entropy.
const ChallengeBytes = 32

// SecurityLevel is the attested key's protection class.
type SecurityLevel string

const (
	SecuritySoftware           SecurityLevel = "software"
	SecurityTrustedEnvironment SecurityLevel = "trusted_environment"
	SecurityStrongBox          SecurityLevel = "strongbox"
)

// Result is what VerifyChain returns on success.
type Result struct {
	// Fingerprint is the SHA-256 of the leaf attestation cert's
	// SubjectPublicKeyInfo. Use this to identify devices in an allowlist.
	Fingerprint [32]byte

	// SecurityLevel reports how strongly the key is protected.
	SecurityLevel SecurityLevel

	// AttestationChallenge is the value the leaf cert claims to have
	// embedded — VerifyChain has already checked this matches the
	// caller-supplied expected challenge, so this is informational.
	AttestationChallenge []byte

	// PackageName + signature digest from attestation extension (when present).
	AttestedPackageName string

	// The leaf cert is exposed so callers can use its public key for
	// further protocol steps (mTLS handshake, etc.).
	Leaf *x509.Certificate

	// RootOfTrust is the device's boot state (0.13.0). Nil when the
	// attestation carried none.
	RootOfTrust *RootOfTrust
}

// Verifier validates Android Key Attestation cert chains.
//
// Configure with [WithRoots] to pass in the trusted Google hardware
// attestation root certs (they rotate; production deployments fetch
// these out-of-band rather than hard-coding).
type Verifier struct {
	roots *x509.CertPool

	// minSecurityLevel rejects chains whose attested key sits in a
	// weaker protection class. Operators can tighten to StrongBox-only
	// for "high-assurance" tenants.
	minSecurityLevel SecurityLevel

	// requireVerifiedBoot rejects devices whose bootloader is unlocked or
	// whose boot image failed verification.
	requireVerifiedBoot bool

	// revocation, when set, checks the chain against Google's published
	// attestation key status list.
	revocation *Revocation

	// now is injected for tests.
	now func() time.Time
}

// WithRequireVerifiedBoot rejects chains whose RootOfTrust reports
// anything other than a locked device in the Verified boot state.
//
// This is the check that separates "a real TEE made this key" from "a
// trustworthy device made this key". A rooted handset with an unlocked
// bootloader still has genuine hardware attestation — its chain verifies
// against the Google root perfectly. Without this option, such a device
// enrols successfully, which for a hospital handset defeats the purpose
// of attesting at all.
//
// A missing RootOfTrust is treated as failure, not as absence of
// evidence: every Keymaster 2+ implementation emits one, so a chain
// without it is either very old or crafted.
func WithRequireVerifiedBoot(require bool) Option {
	return func(v *Verifier) { v.requireVerifiedBoot = require }
}

// WithRevocation enables checking against Google's attestation key status
// list. See [Revocation] for why this matters.
func WithRevocation(r *Revocation) Option {
	return func(v *Verifier) { v.revocation = r }
}

// Option follows the functional-options pattern.
type Option func(*Verifier)

// WithRoots installs trusted Google hardware-attestation root certificates.
// Call once at startup with the latest published roots.
func WithRoots(rootPEM []byte) Option {
	return func(v *Verifier) {
		if v.roots == nil {
			v.roots = x509.NewCertPool()
		}
		v.roots.AppendCertsFromPEM(rootPEM)
	}
}

// WithMinSecurityLevel sets the floor for [Result.SecurityLevel]. Default
// is TrustedEnvironment — we reject software-backed keys regardless.
func WithMinSecurityLevel(level SecurityLevel) Option {
	return func(v *Verifier) { v.minSecurityLevel = level }
}

// WithNow injects a clock for tests.
func WithNow(now func() time.Time) Option {
	return func(v *Verifier) { v.now = now }
}

// New returns a Verifier configured with the given options.
func New(opts ...Option) *Verifier {
	v := &Verifier{
		minSecurityLevel: SecurityTrustedEnvironment,
		now:              func() time.Time { return time.Now().UTC() },
	}
	for _, opt := range opts {
		opt(v)
	}
	if v.roots == nil {
		v.roots = x509.NewCertPool()
	}
	return v
}

// VerifyChain checks an Android Key Attestation cert chain.
//
//   - chainPEM: PEM-encoded chain, leaf first, root last (or omitted if
//     present in the verifier's root pool).
//   - expectedChallenge: the 32-byte nonce the controller issued to this
//     device. Must match the value embedded in the leaf cert by Keystore.
//
// Returns a [Result] describing the attested key's properties. Callers
// can then look up Result.Fingerprint in their allowlist.
func (v *Verifier) VerifyChain(chainPEM []byte, expectedChallenge []byte) (*Result, error) {
	chain, err := parseChainPEM(chainPEM)
	if err != nil {
		return nil, fmt.Errorf("parse chain: %w", err)
	}
	if len(chain) == 0 {
		return nil, errors.New("empty cert chain")
	}

	leaf := chain[0]

	// 1. Path validation: leaf chains to a trusted root.
	intermediates := x509.NewCertPool()
	for i := 1; i < len(chain); i++ {
		intermediates.AddCert(chain[i])
	}
	verifyOpts := x509.VerifyOptions{
		Roots:         v.roots,
		Intermediates: intermediates,
		CurrentTime:   v.now(),
		// Don't require a specific EKU — Google's attestation chains
		// don't all set ExtKeyUsageClientAuth.
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}
	if _, err := leaf.Verify(verifyOpts); err != nil {
		return nil, fmt.Errorf("chain verification: %w", err)
	}

	// 2. Find and parse the Android attestation extension.
	ext, err := findAttestationExtension(leaf)
	if err != nil {
		return nil, fmt.Errorf("attestation extension: %w", err)
	}

	// 3. Challenge match — replay protection.
	if !equalBytes(ext.AttestationChallenge, expectedChallenge) {
		return nil, fmt.Errorf("attestation challenge mismatch (have %d bytes, want %d)",
			len(ext.AttestationChallenge), len(expectedChallenge))
	}

	// 4. Security level floor.
	level := levelFromInt(ext.AttestationSecurityLevel)
	if !levelGE(level, v.minSecurityLevel) {
		return nil, fmt.Errorf("security level %s is below required %s",
			level, v.minSecurityLevel)
	}

	// 5. Boot state. See WithRequireVerifiedBoot.
	if v.requireVerifiedBoot {
		rot := ext.RootOfTrust
		if rot == nil {
			return nil, errors.New(
				"attestation carries no RootOfTrust; cannot confirm the device is unmodified")
		}
		if !rot.DeviceLocked {
			return nil, errors.New("device bootloader is unlocked")
		}
		if rot.VerifiedBootState != BootVerified {
			return nil, fmt.Errorf("verified boot state is %s, want verified",
				rot.VerifiedBootState)
		}
	}

	// 6. Revocation. Done after the cheaper checks so a malformed chain
	//    doesn't consume a status-list lookup, but before returning
	//    success — a revoked batch key must never yield a Result.
	if v.revocation != nil {
		serials := make([]*big.Int, 0, len(chain))
		for _, c := range chain {
			serials = append(serials, c.SerialNumber)
		}
		revoked, entry, err := v.revocation.Check(serials)
		if err != nil {
			return nil, fmt.Errorf("revocation check: %w", err)
		}
		if revoked != "" {
			return nil, fmt.Errorf(
				"attestation key %s is %s (%s)", revoked, entry.Status, entry.Reason)
		}
	}

	// 7. Compute device fingerprint from the LEAF's public key. Stable
	//    across re-registrations on the same device because the same
	//    Keystore alias generates a fresh keypair, but the *next* cert
	//    up the chain (the batch attestation key) stays the same. We
	//    fingerprint the leaf for tighter binding to "this specific
	//    enrolment", but you can also use the parent for "this device
	//    in general"; the allowlist UI lets admins pick.
	fp, err := publicKeyFingerprint(leaf.PublicKey)
	if err != nil {
		return nil, err
	}

	res := &Result{
		Fingerprint:          fp,
		SecurityLevel:        level,
		AttestationChallenge: ext.AttestationChallenge,
		AttestedPackageName:  ext.AttestedPackageName,
		Leaf:                 leaf,
		RootOfTrust:          ext.RootOfTrust,
	}
	return res, nil
}

// FingerprintFromLeafPEM is a convenience for the admin enrolment flow:
// given just a leaf cert PEM (e.g. pasted from a developer console), it
// returns the SHA-256 fingerprint that the allowlist would match against.
func FingerprintFromLeafPEM(leafPEM []byte) ([32]byte, error) {
	block, _ := pem.Decode(leafPEM)
	if block == nil {
		return [32]byte{}, errors.New("no PEM block found")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return [32]byte{}, err
	}
	return publicKeyFingerprint(cert.PublicKey)
}

// --- internals ---------------------------------------------------------

func parseChainPEM(input []byte) ([]*x509.Certificate, error) {
	var chain []*x509.Certificate
	rest := input
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		chain = append(chain, c)
	}
	return chain, nil
}

// publicKeyFingerprint hashes the SubjectPublicKeyInfo of a public key.
// Stable for a given (key type, curve, point) tuple.
func publicKeyFingerprint(pub crypto.PublicKey) ([32]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return [32]byte{}, fmt.Errorf("marshal pubkey: %w", err)
	}
	return sha256.Sum256(der), nil
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var d byte
	for i := range a {
		d |= a[i] ^ b[i]
	}
	return d == 0
}

// AttestationOID is the Android Key Attestation extension OID.
// See https://source.android.com/docs/security/features/keystore/attestation.
var AttestationOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 1, 17}

func findAttestationExtension(leaf *x509.Certificate) (*Extension, error) {
	for _, ext := range leaf.Extensions {
		if ext.Id.Equal(AttestationOID) {
			return parseExtension(ext.Value)
		}
	}
	return nil, errors.New("Android attestation extension not present")
}

// levelFromInt maps the Keymaster integer encoding to our enum.
//
// Keymaster encoding: 0=Software, 1=TrustedEnvironment, 2=StrongBox.
func levelFromInt(v int) SecurityLevel {
	switch v {
	case 1:
		return SecurityTrustedEnvironment
	case 2:
		return SecurityStrongBox
	default:
		return SecuritySoftware
	}
}

// levelGE returns true if `have` is at least as strong as `min`.
func levelGE(have, min SecurityLevel) bool {
	rank := map[SecurityLevel]int{
		SecuritySoftware:           0,
		SecurityTrustedEnvironment: 1,
		SecurityStrongBox:          2,
	}
	return rank[have] >= rank[min]
}
