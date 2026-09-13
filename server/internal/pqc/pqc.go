// Package pqc provides ML-KEM-768 (FIPS 203) key encapsulation for
// AidotVpn's hybrid post-quantum PSK derivation.
//
// Why hybrid:
//
//	The WireGuard handshake uses a classical Curve25519 ECDH plus an
//	optional pre-shared key (PSK). If/when a sufficiently capable quantum
//	computer breaks Curve25519, an attacker who recorded today's
//	handshakes could replay them — UNLESS the PSK contributed independent,
//	PQ-secure entropy. Hybrid post-quantum PSKs guarantee that the
//	resulting session key is at least as secure as the strongest
//	contribution, so the system is "post-quantum safe" without
//	abandoning the auditable, FIPS-evaluated classical primitives.
//
// Construction (matches the WireGuard PQ-PSK draft):
//
//  1. Each tenant has a long-lived ML-KEM-768 keypair (decap key on
//     controller, encap key shared with mobile clients via Register
//     response).
//  2. Per-device:
//     a. Server generates a fresh classical 32-byte PSK_classic.
//     b. Mobile client encapsulates against the tenant's encap key,
//     producing a 32-byte shared_secret K_kem and a 1088-byte
//     ciphertext.
//     c. Client sends the ciphertext back; server decapsulates to
//     derive the same K_kem.
//     d. Both sides compute PSK_final = HKDF-SHA256(
//     IKM=PSK_classic || K_kem,
//     salt="aidotvpn-pqc-v1",
//     info=device_id_bytes,
//     len=32 ).
//  3. PSK_final is what the WG handshake uses.
//
// Status (corrected in 0.20.0):
//
//	Steps 1, 2a, 2c and 2d are implemented and wired — see store.go for
//	the tenant keypair and devices.allocateAndIssue for the derivation.
//
//	Step 2b (client encapsulation) is NOT implemented. This comment
//	previously claimed it lived in :core/PqcKemClient.kt; that file has
//	never existed. Android has no ML-KEM without adding BouncyCastle
//	(~8MB), which is a dependency decision the deployment should make
//	rather than inherit — see docs/pqc-ko.md.
//
//	The handshake works regardless because PSK_classic alone is a valid
//	PSK. Every client today takes that path.
package pqc

import (
	"crypto/hkdf"
	"crypto/mlkem"
	"crypto/sha256"
	"errors"
	"fmt"
)

// Algorithm identifiers persisted in tenant_kem_keys.algorithm.
const (
	AlgorithmMLKEM768 = "ml-kem-768"
)

// EncapKeySize is the size of an ML-KEM-768 public (encapsulation) key.
const EncapKeySize = 1184

// CiphertextSize is the size of an ML-KEM-768 ciphertext.
const CiphertextSize = 1088

// SharedSecretSize is the size of the symmetric secret returned by
// encapsulation/decapsulation.
const SharedSecretSize = 32

// GenerateTenantKeypair returns a fresh ML-KEM-768 keypair for a tenant.
// The encap key (public) is shipped to clients in Register responses;
// the decap key (private) stays in tenant_kem_keys.
func GenerateTenantKeypair() (encapKey []byte, decapKey []byte, err error) {
	dk, err := mlkem.GenerateKey768()
	if err != nil {
		return nil, nil, fmt.Errorf("GenerateKey768: %w", err)
	}
	ek := dk.EncapsulationKey()
	return ek.Bytes(), dk.Bytes(), nil
}

// Decapsulate runs the server-side step of the KEM, recovering the same
// 32-byte shared secret the client computed via encapsulation.
func Decapsulate(decapKey []byte, ciphertext []byte) ([]byte, error) {
	if len(ciphertext) != CiphertextSize {
		return nil, fmt.Errorf("ciphertext size %d, want %d", len(ciphertext), CiphertextSize)
	}
	dk, err := mlkem.NewDecapsulationKey768(decapKey)
	if err != nil {
		return nil, fmt.Errorf("parse decap key: %w", err)
	}
	ss, err := dk.Decapsulate(ciphertext)
	if err != nil {
		return nil, fmt.Errorf("Decapsulate: %w", err)
	}
	return ss, nil
}

// Encapsulate is the client-side step. Useful for server-side tests; in
// production the mobile client invokes its own KEM library.
func Encapsulate(encapKey []byte) (sharedSecret, ciphertext []byte, err error) {
	if len(encapKey) != EncapKeySize {
		return nil, nil, fmt.Errorf("encap key size %d, want %d", len(encapKey), EncapKeySize)
	}
	ek, err := mlkem.NewEncapsulationKey768(encapKey)
	if err != nil {
		return nil, nil, fmt.Errorf("parse encap key: %w", err)
	}
	ss, ct := ek.Encapsulate()
	return ss, ct, nil
}

// HybridPSK derives the final 32-byte WireGuard PSK from the classical
// PSK and the KEM-derived shared secret using HKDF-SHA256.
//
// The salt and info strings match the values the mobile client computes,
// keeping the two ends of the tunnel in agreement without any
// out-of-band negotiation.
func HybridPSK(classicalPSK, kemSharedSecret []byte, deviceIDBytes []byte) ([]byte, error) {
	if len(classicalPSK) != 32 {
		return nil, errors.New("classical PSK must be 32 bytes")
	}
	if len(kemSharedSecret) != SharedSecretSize {
		return nil, fmt.Errorf("KEM shared secret %d bytes, want %d", len(kemSharedSecret), SharedSecretSize)
	}
	ikm := make([]byte, 0, 64)
	ikm = append(ikm, classicalPSK...)
	ikm = append(ikm, kemSharedSecret...)

	const salt = "aidotvpn-pqc-v1"
	out, err := hkdf.Key(sha256.New, ikm, []byte(salt), string(deviceIDBytes), 32)
	if err != nil {
		return nil, fmt.Errorf("hkdf: %w", err)
	}
	return out, nil
}
