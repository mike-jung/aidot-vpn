package auth

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"net/url"
	"strings"
	"testing"

	"github.com/aidotvpn/server/internal/domain"
)

// makeCSR builds a PKCS#10 CSR signed with the given key. Used to feed
// IssueFromCSR in tests without standing up a full mobile client.
func makeCSR(t *testing.T, signer crypto.Signer, sigAlg x509.SignatureAlgorithm) []byte {
	t.Helper()
	tmpl := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: "client-supplied-cn-should-be-ignored",
		},
		// CSR includes a SAN the client wishes for; controller MUST ignore.
		URIs:               []*url.URL{{Scheme: "urn", Opaque: "aidotvpn:device:00000000-0000-0000-0000-000000000000"}},
		SignatureAlgorithm: sigAlg,
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, signer)
	if err != nil {
		t.Fatalf("CreateCertificateRequest: %v", err)
	}
	return der
}

func TestIssueFromCSR_HappyPath_ECDSAP256(t *testing.T) {
	ca, err := NewCA(CAOptions{})
	if err != nil {
		t.Fatalf("NewCA: %v", err)
	}
	devKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der := makeCSR(t, devKey, x509.ECDSAWithSHA256)
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		t.Fatalf("parse CSR: %v", err)
	}

	deviceID := domain.NewID()
	res, err := ca.IssueFromCSR(CSRIssuanceRequest{
		DeviceID: deviceID,
		CSR:      csr,
	})
	if err != nil {
		t.Fatalf("IssueFromCSR: %v", err)
	}
	if len(res.CertPEM) == 0 {
		t.Fatal("empty cert PEM")
	}

	// Decode the issued cert and verify subject + SAN follow controller
	// canonical form (NOT what the CSR requested).
	block, _ := pem.Decode(res.CertPEM)
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	if leaf.Subject.CommonName != deviceID.String() {
		t.Errorf("cert CN = %q, want %q (CSR's CN should have been overridden)",
			leaf.Subject.CommonName, deviceID.String())
	}
	if len(leaf.URIs) != 1 ||
		leaf.URIs[0].String() != "urn:aidotvpn:device:"+deviceID.String() {
		t.Errorf("cert URI SAN = %v, want urn:aidotvpn:device:%s", leaf.URIs, deviceID)
	}
	// Public key in the cert must match the CSR's key, NOT a server-generated one.
	leafPub, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("cert pubkey type %T, want *ecdsa.PublicKey", leaf.PublicKey)
	}
	if leafPub.X.Cmp(devKey.PublicKey.X) != 0 || leafPub.Y.Cmp(devKey.PublicKey.Y) != 0 {
		t.Error("cert pubkey does not match CSR pubkey")
	}
}

func TestIssueFromCSR_RejectsBadSignature(t *testing.T) {
	ca, _ := NewCA(CAOptions{})
	devKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der := makeCSR(t, devKey, x509.ECDSAWithSHA256)
	// Corrupt the last byte (which lives inside the signature region).
	der[len(der)-1] ^= 0xFF
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		// Some forms of corruption fail at parse; that's also acceptable.
		return
	}
	_, err = ca.IssueFromCSR(CSRIssuanceRequest{DeviceID: domain.NewID(), CSR: csr})
	if err == nil {
		t.Error("expected IssueFromCSR to reject corrupt CSR signature")
	}
}

func TestIssueFromCSR_RejectsWeakRSA(t *testing.T) {
	ca, _ := NewCA(CAOptions{})
	weak, _ := rsa.GenerateKey(rand.Reader, 1024) // below 2048 minimum
	der := makeCSR(t, weak, x509.SHA256WithRSA)
	csr, _ := x509.ParseCertificateRequest(der)
	_, err := ca.IssueFromCSR(CSRIssuanceRequest{DeviceID: domain.NewID(), CSR: csr})
	if err == nil {
		t.Error("expected weak RSA key to be rejected")
	}
	if !strings.Contains(err.Error(), "below minimum") {
		t.Errorf("error message: %v", err)
	}
}

func TestIssueFromCSR_AcceptsEd25519(t *testing.T) {
	ca, _ := NewCA(CAOptions{})
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	_ = pub
	tmpl := &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "ed25519-client"},
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, priv)
	if err != nil {
		t.Fatalf("create CSR: %v", err)
	}
	csr, _ := x509.ParseCertificateRequest(der)
	if _, err := ca.IssueFromCSR(CSRIssuanceRequest{DeviceID: domain.NewID(), CSR: csr}); err != nil {
		t.Errorf("Ed25519 CSR rejected: %v", err)
	}
}

func TestIssueFromCSR_RejectsZeroDeviceID(t *testing.T) {
	ca, _ := NewCA(CAOptions{})
	devKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der := makeCSR(t, devKey, x509.ECDSAWithSHA256)
	csr, _ := x509.ParseCertificateRequest(der)
	_, err := ca.IssueFromCSR(CSRIssuanceRequest{CSR: csr})
	if err == nil {
		t.Error("expected zero DeviceID to be rejected")
	}
}

func TestIssueFromCSR_LifetimeCap(t *testing.T) {
	ca, _ := NewCA(CAOptions{})
	devKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der := makeCSR(t, devKey, x509.ECDSAWithSHA256)
	csr, _ := x509.ParseCertificateRequest(der)

	res, err := ca.IssueFromCSR(CSRIssuanceRequest{
		DeviceID: domain.NewID(),
		CSR:      csr,
		Lifetime: 365 * 24 * 60 * 60 * 1_000_000_000, // 1 year, way over cap
	})
	if err != nil {
		t.Fatalf("IssueFromCSR: %v", err)
	}
	gap := res.NotAfter.Sub(res.NotBefore)
	if gap > MaxClientCertLifetime {
		t.Errorf("cert lifetime %v exceeds cap %v", gap, MaxClientCertLifetime)
	}
}
