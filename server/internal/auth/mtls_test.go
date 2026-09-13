package auth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"
	"time"

	"github.com/aidotvpn/server/internal/domain"
)

func TestNewCA_SelfSigned_Verifies(t *testing.T) {
	ca, err := NewCA(CAOptions{CommonName: "test-ca"})
	if err != nil {
		t.Fatalf("NewCA: %v", err)
	}
	cert := ca.Cert()
	if !cert.IsCA {
		t.Errorf("CA cert IsCA=false")
	}
	if !cert.BasicConstraintsValid {
		t.Errorf("BasicConstraintsValid=false")
	}
	// Self-signed: signature verifies against its own public key.
	if err := cert.CheckSignatureFrom(cert); err != nil {
		t.Errorf("self-sign verify: %v", err)
	}
	// Subject pieces present.
	if cert.Subject.CommonName != "test-ca" {
		t.Errorf("CN: %q", cert.Subject.CommonName)
	}
}

func TestCA_PEMRoundtrip(t *testing.T) {
	ca, err := NewCA(CAOptions{CommonName: "roundtrip"})
	if err != nil {
		t.Fatalf("NewCA: %v", err)
	}
	certPEM := ca.CertPEM()
	keyPEM, err := ca.KeyPEM()
	if err != nil {
		t.Fatalf("KeyPEM: %v", err)
	}
	if !strings.Contains(string(certPEM), "BEGIN CERTIFICATE") {
		t.Errorf("cert PEM looks wrong: %s", certPEM)
	}
	if !strings.Contains(string(keyPEM), "BEGIN PRIVATE KEY") {
		t.Errorf("key PEM looks wrong: %s", keyPEM[:80])
	}
	loaded, err := LoadCA(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("LoadCA: %v", err)
	}
	if loaded.Cert().Subject.CommonName != "roundtrip" {
		t.Errorf("CN after load: %q", loaded.Cert().Subject.CommonName)
	}
}

func TestIssue_BasicSuccess(t *testing.T) {
	ca, _ := NewCA(CAOptions{})

	// Device key (ECDSA P-256, like a real WG-adjacent control key).
	devKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	devID := domain.NewID()

	res, err := ca.Issue(IssuanceRequest{
		DeviceID:  devID,
		PublicKey: &devKey.PublicKey,
		Lifetime:  6 * time.Hour,
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if len(res.SerialBytes) != 20 {
		t.Errorf("serial bytes len: %d", len(res.SerialBytes))
	}
	if len(res.FingerprintSHA256) != 32 {
		t.Errorf("fingerprint len: %d", len(res.FingerprintSHA256))
	}

	// Parse the issued cert and validate it against the CA pool.
	block, _ := pem.Decode(res.CertPEM)
	if block == nil {
		t.Fatal("no PEM block")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	if leaf.Subject.CommonName != devID.String() {
		t.Errorf("CN mismatch: %q vs %q", leaf.Subject.CommonName, devID.String())
	}
	// Should have URI SAN urn:aidotvpn:device:<uuid>
	if len(leaf.URIs) != 1 {
		t.Fatalf("expected 1 URI SAN, got %d", len(leaf.URIs))
	}
	want := "urn:aidotvpn:device:" + devID.String()
	if leaf.URIs[0].String() != want {
		t.Errorf("URI SAN: got %q, want %q", leaf.URIs[0].String(), want)
	}
	// Validate against CA pool.
	pool := x509.NewCertPool()
	pool.AddCert(ca.Cert())
	_, err = leaf.Verify(x509.VerifyOptions{
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		// Use the leaf's NotBefore as anchor so test runs in time.
		CurrentTime: leaf.NotBefore.Add(time.Minute),
	})
	if err != nil {
		t.Errorf("Verify against CA: %v", err)
	}
}

func TestIssue_LifetimeCap(t *testing.T) {
	ca, _ := NewCA(CAOptions{})
	devKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	// Ask for 1 year. Result must be capped at MaxClientCertLifetime (24h).
	notBefore := time.Now().UTC()
	res, err := ca.Issue(IssuanceRequest{
		DeviceID:  domain.NewID(),
		PublicKey: &devKey.PublicKey,
		NotBefore: notBefore,
		Lifetime:  365 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	got := res.NotAfter.Sub(res.NotBefore)
	if got != MaxClientCertLifetime {
		t.Errorf("lifetime cap not enforced: got %v, want %v", got, MaxClientCertLifetime)
	}
}

func TestIssue_RejectsZeroDeviceID(t *testing.T) {
	ca, _ := NewCA(CAOptions{})
	devKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if _, err := ca.Issue(IssuanceRequest{
		DeviceID:  domain.ID{}, // zero
		PublicKey: &devKey.PublicKey,
	}); err == nil {
		t.Fatal("zero DeviceID was accepted")
	}
}

func TestIssue_RejectsNilPublicKey(t *testing.T) {
	ca, _ := NewCA(CAOptions{})
	if _, err := ca.Issue(IssuanceRequest{
		DeviceID: domain.NewID(),
	}); err == nil {
		t.Fatal("nil PublicKey was accepted")
	}
}

func TestIssue_DifferentSerials(t *testing.T) {
	ca, _ := NewCA(CAOptions{})
	devKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	const N = 50
	seen := make(map[string]bool, N)
	for i := 0; i < N; i++ {
		res, err := ca.Issue(IssuanceRequest{
			DeviceID:  domain.NewID(),
			PublicKey: &devKey.PublicKey,
		})
		if err != nil {
			t.Fatalf("Issue %d: %v", i, err)
		}
		key := string(res.SerialBytes)
		if seen[key] {
			t.Fatalf("duplicate serial at i=%d", i)
		}
		seen[key] = true
	}
}

func TestIssue_RSAClientKey(t *testing.T) {
	ca, _ := NewCA(CAOptions{KeyType: ECDSAP256})
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	res, err := ca.Issue(IssuanceRequest{
		DeviceID:  domain.NewID(),
		PublicKey: &rsaKey.PublicKey,
	})
	if err != nil {
		t.Fatalf("Issue with RSA client key: %v", err)
	}
	block, _ := pem.Decode(res.CertPEM)
	leaf, _ := x509.ParseCertificate(block.Bytes)
	if _, ok := leaf.PublicKey.(*rsa.PublicKey); !ok {
		t.Errorf("issued cert's public key is %T, want *rsa.PublicKey", leaf.PublicKey)
	}
}

func TestLoadCA_RejectsNonCA(t *testing.T) {
	// Issue a leaf and try to load it as a CA — must fail.
	ca, _ := NewCA(CAOptions{})
	devKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	res, _ := ca.Issue(IssuanceRequest{
		DeviceID:  domain.NewID(),
		PublicKey: &devKey.PublicKey,
	})
	devKeyDER, _ := x509.MarshalECPrivateKey(devKey)
	devKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: devKeyDER})
	if _, err := LoadCA(res.CertPEM, devKeyPEM); err == nil {
		t.Fatal("LoadCA accepted a non-CA leaf cert")
	}
}
