package devices

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"testing"
)

// makeCSRPEM builds a fresh ECDSA P-256 keypair, wraps a CSR around it,
// and returns the PEM bytes the controller expects.
func makeCSRPEM(t *testing.T) []byte {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate EC key: %v", err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:            pkix.Name{CommonName: "client-side-ignored"},
		SignatureAlgorithm: x509.ECDSAWithSHA256,
	}, priv)
	if err != nil {
		t.Fatalf("create CSR: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}

func TestRegister_WithCSR_UsesClientPubkey_Integration(t *testing.T) {
	db := requireTestDB(t)
	resetDB(t, db)
	uid := seedUser(t, db)
	svc := makeService(t, db)

	csrPEM := makeCSRPEM(t)
	res, err := svc.Register(context.Background(), RegisterParams{
		UserID:           uid,
		InstallID:        "11111111-1111-7111-8111-111111111111",
		DisplayName:      "csr-test",
		Platform:         PlatformAndroid,
		AppVersion:       "0.2.0",
		DevicePublicKey:  randomKey(t),
		AttestationToken: "ok",
		ClientCertCSRPEM: csrPEM,
	})
	if err != nil {
		t.Fatalf("Register with CSR: %v", err)
	}

	// Decode the issued cert; its public key must match the CSR's pubkey.
	block, _ := pem.Decode(res.Allocation.ClientCertPEM)
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	csrBlock, _ := pem.Decode(csrPEM)
	csr, _ := x509.ParseCertificateRequest(csrBlock.Bytes)

	leafEC, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("leaf cert pubkey type %T", leaf.PublicKey)
	}
	csrEC := csr.PublicKey.(*ecdsa.PublicKey)
	if leafEC.X.Cmp(csrEC.X) != 0 || leafEC.Y.Cmp(csrEC.Y) != 0 {
		t.Error("issued cert pubkey != CSR pubkey (server should never have generated its own)")
	}

	// Subject CN must be the device id, not whatever was in the CSR.
	if leaf.Subject.CommonName != res.Device.ID.String() {
		t.Errorf("CN = %q, want %q", leaf.Subject.CommonName, res.Device.ID.String())
	}
}

func TestRegister_WithoutCSR_FallsBackToServerKey_Integration(t *testing.T) {
	db := requireTestDB(t)
	resetDB(t, db)
	uid := seedUser(t, db)
	svc := makeService(t, db)

	res, err := svc.Register(context.Background(), RegisterParams{
		UserID:           uid,
		InstallID:        "22222222-2222-7222-8222-222222222222",
		DisplayName:      "legacy-test",
		Platform:         PlatformAndroid,
		DevicePublicKey:  randomKey(t),
		AttestationToken: "ok",
		// No CSR — controller should fall back to server-generated key.
	})
	if err != nil {
		t.Fatalf("Register without CSR: %v", err)
	}
	if len(res.Allocation.ClientCertPEM) == 0 {
		t.Fatal("legacy path produced empty cert")
	}
}

func TestRegister_WithCorruptedCSR_Errors_Integration(t *testing.T) {
	db := requireTestDB(t)
	resetDB(t, db)
	uid := seedUser(t, db)
	svc := makeService(t, db)

	_, err := svc.Register(context.Background(), RegisterParams{
		UserID:           uid,
		InstallID:        "33333333-3333-7333-8333-333333333333",
		DisplayName:      "corrupt-test",
		Platform:         PlatformAndroid,
		DevicePublicKey:  randomKey(t),
		AttestationToken: "ok",
		ClientCertCSRPEM: []byte("-----BEGIN CERTIFICATE REQUEST-----\nXXXX\n-----END CERTIFICATE REQUEST-----\n"),
	})
	if err == nil {
		t.Error("expected Register to reject corrupt CSR")
	}
}

func TestRotateKey_WithCSR_Integration(t *testing.T) {
	db := requireTestDB(t)
	resetDB(t, db)
	uid := seedUser(t, db)
	svc := makeService(t, db)

	first, err := svc.Register(context.Background(), RegisterParams{
		UserID: uid, InstallID: "44444444-4444-7444-8444-444444444444",
		DisplayName: "rotate-csr", Platform: PlatformAndroid,
		DevicePublicKey: randomKey(t), AttestationToken: "ok",
		ClientCertCSRPEM: makeCSRPEM(t),
	})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	newCSR := makeCSRPEM(t)
	rot, err := svc.RotateKey(context.Background(), RotateKeyParams{
		DeviceID:           first.Device.ID,
		NewDevicePublicKey: randomKey(t),
		ClientCertCSRPEM:   newCSR,
	})
	if err != nil {
		t.Fatalf("RotateKey: %v", err)
	}

	// New cert's pubkey must match the new CSR.
	block, _ := pem.Decode(rot.Allocation.ClientCertPEM)
	leaf, _ := x509.ParseCertificate(block.Bytes)
	csrBlock, _ := pem.Decode(newCSR)
	csr, _ := x509.ParseCertificateRequest(csrBlock.Bytes)
	leafEC := leaf.PublicKey.(*ecdsa.PublicKey)
	csrEC := csr.PublicKey.(*ecdsa.PublicKey)
	if leafEC.X.Cmp(csrEC.X) != 0 {
		t.Error("rotated cert pubkey != new CSR pubkey")
	}

	// Old cert and new cert must differ.
	if string(first.Allocation.ClientCertPEM) == string(rot.Allocation.ClientCertPEM) {
		t.Error("rotated cert should differ from initial")
	}
}
