package attestation

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

// buildKeyDescription DER-encodes a synthetic Android Key Attestation
// extension payload. We don't reproduce every single AuthorizationList
// field — we just emit the outer KeyDescription with the attestation
// challenge and security level fields the verifier consumes, plus an
// empty teeEnforced SEQUENCE.
func buildKeyDescription(t *testing.T, challenge []byte, secLevel int) []byte {
	t.Helper()

	emptyAuth := mustMarshal(t, struct{}{})

	desc := struct {
		AttestationVersion       int
		AttestationSecurityLevel asn1.Enumerated
		KeymasterVersion         int
		KeymasterSecurityLevel   asn1.Enumerated
		AttestationChallenge     []byte
		UniqueId                 []byte
		SoftwareEnforced         asn1.RawValue
		TeeEnforced              asn1.RawValue
	}{
		AttestationVersion:       300,
		AttestationSecurityLevel: asn1.Enumerated(secLevel),
		KeymasterVersion:         300,
		KeymasterSecurityLevel:   asn1.Enumerated(secLevel),
		AttestationChallenge:     challenge,
		UniqueId:                 []byte{},
		SoftwareEnforced:         asn1.RawValue{FullBytes: emptyAuth},
		TeeEnforced:              asn1.RawValue{FullBytes: emptyAuth},
	}
	der, err := asn1.Marshal(desc)
	if err != nil {
		t.Fatalf("marshal KeyDescription: %v", err)
	}
	return der
}

func mustMarshal(t *testing.T, v interface{}) []byte {
	t.Helper()
	b, err := asn1.Marshal(v)
	if err != nil {
		t.Fatalf("asn1.Marshal: %v", err)
	}
	return b
}

// buildSyntheticChain builds a 3-cert chain that mimics the structure of
// a real Android attestation chain: leaf -> intermediate -> root.
// The leaf carries a forged "attestation extension" with the given
// challenge and security level. Used only in tests.
func buildSyntheticChain(t *testing.T, challenge []byte, secLevel int) (chainPEM []byte, rootPEM []byte) {
	t.Helper()

	// Root CA
	rootKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rootTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Synthetic AOSP Attestation Root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	rootDER, _ := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	rootCert, _ := x509.ParseCertificate(rootDER)

	// Intermediate
	intKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	intTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "Synthetic Attestation Intermediate"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(12 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	intDER, _ := x509.CreateCertificate(rand.Reader, intTmpl, rootCert, &intKey.PublicKey, rootKey)
	intCert, _ := x509.ParseCertificate(intDER)

	// Leaf with attestation extension
	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: "Attested device key"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtraExtensions: []pkix.Extension{
			{
				Id:    AttestationOID,
				Value: buildKeyDescription(t, challenge, secLevel),
			},
		},
	}
	leafDER, _ := x509.CreateCertificate(rand.Reader, leafTmpl, intCert, &leafKey.PublicKey, intKey)

	chainPEM = pemEncode(leafDER, intDER, rootDER)
	rootPEM = pemEncode(rootDER)
	return
}

func pemEncode(ders ...[]byte) []byte {
	var out []byte
	for _, der := range ders {
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	return out
}

func TestVerifyChain_HappyPath(t *testing.T) {
	challenge := []byte("0123456789abcdef0123456789abcdef")
	chain, root := buildSyntheticChain(t, challenge, 1) // TrustedEnvironment

	v := New(WithRoots(root))
	res, err := v.VerifyChain(chain, challenge)
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if res.SecurityLevel != SecurityTrustedEnvironment {
		t.Errorf("security level: %s", res.SecurityLevel)
	}
	if string(res.AttestationChallenge) != string(challenge) {
		t.Error("challenge not propagated")
	}
	// Fingerprint must be 32 bytes and stable.
	if len(res.Fingerprint) != 32 {
		t.Errorf("fp length %d", len(res.Fingerprint))
	}
	res2, _ := v.VerifyChain(chain, challenge)
	if res.Fingerprint != res2.Fingerprint {
		t.Error("fingerprint not stable across verifications")
	}
}

func TestVerifyChain_RejectsChallengeMismatch(t *testing.T) {
	chain, root := buildSyntheticChain(t, []byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"), 1)
	v := New(WithRoots(root))
	_, err := v.VerifyChain(chain, []byte("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"))
	if err == nil {
		t.Fatal("expected challenge mismatch error")
	}
}

func TestVerifyChain_RejectsUnknownRoot(t *testing.T) {
	challenge := []byte("0123456789abcdef0123456789abcdef")
	chain, _ := buildSyntheticChain(t, challenge, 1)
	v := New() // no roots installed
	_, err := v.VerifyChain(chain, challenge)
	if err == nil {
		t.Fatal("expected chain verification to fail without trusted root")
	}
}

func TestVerifyChain_RejectsSoftwareSecurity(t *testing.T) {
	challenge := []byte("0123456789abcdef0123456789abcdef")
	// secLevel=0 (Software) should be rejected by default
	// (min level = TrustedEnvironment).
	chain, root := buildSyntheticChain(t, challenge, 0)
	v := New(WithRoots(root))
	_, err := v.VerifyChain(chain, challenge)
	if err == nil {
		t.Fatal("expected software-backed key to be rejected")
	}
}

func TestVerifyChain_AcceptsStrongBoxWithStrictPolicy(t *testing.T) {
	challenge := []byte("0123456789abcdef0123456789abcdef")
	chain, root := buildSyntheticChain(t, challenge, 2) // StrongBox

	v := New(WithRoots(root), WithMinSecurityLevel(SecurityStrongBox))
	res, err := v.VerifyChain(chain, challenge)
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if res.SecurityLevel != SecurityStrongBox {
		t.Errorf("expected StrongBox, got %s", res.SecurityLevel)
	}
}

func TestVerifyChain_RejectsTrustedEnvWhenStrongBoxRequired(t *testing.T) {
	challenge := []byte("0123456789abcdef0123456789abcdef")
	chain, root := buildSyntheticChain(t, challenge, 1) // TrustedEnv only

	v := New(WithRoots(root), WithMinSecurityLevel(SecurityStrongBox))
	_, err := v.VerifyChain(chain, challenge)
	if err == nil {
		t.Fatal("expected TEE-only chain to be rejected when StrongBox required")
	}
}

func TestFingerprintFromLeafPEM_StableAcrossInvocations(t *testing.T) {
	chain, _ := buildSyntheticChain(t, []byte("0123456789abcdef0123456789abcdef"), 1)
	// Extract just the leaf (first PEM block).
	block, _ := pem.Decode(chain)
	leafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: block.Bytes})

	fp1, err := FingerprintFromLeafPEM(leafPEM)
	if err != nil {
		t.Fatalf("fp1: %v", err)
	}
	fp2, _ := FingerprintFromLeafPEM(leafPEM)
	if fp1 != fp2 {
		t.Error("fingerprint not stable")
	}
}
