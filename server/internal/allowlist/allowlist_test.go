package allowlist

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"testing"
	"time"

	_ "github.com/go-sql-driver/mysql"

	"github.com/aidotvpn/server/internal/attestation"
	"github.com/aidotvpn/server/internal/domain"
)

// requireTestDB and friends are minimal copies of the helpers in
// internal/devices/service_test.go — duplicating one helper avoids a
// circular package dependency between two _test.go files.
func requireTestDB(t *testing.T) *sql.DB {
	t.Helper()
	dsn := os.Getenv("AIDOTVPN_TEST_DSN")
	if dsn == "" {
		t.Skip("AIDOTVPN_TEST_DSN not set")
	}
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := db.PingContext(context.Background()); err != nil {
		t.Fatalf("ping: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func defaultTenantID() domain.ID {
	id, _ := domain.ParseID("019650000000700080000000000000A1")
	return id
}

func resetDB(t *testing.T, db *sql.DB) {
	t.Helper()
	stmts := []string{
		"SET FOREIGN_KEY_CHECKS=0",
		"TRUNCATE TABLE device_attestations_allowlist",
		"TRUNCATE TABLE attestation_challenges",
		"TRUNCATE TABLE attestation_records",
		"TRUNCATE TABLE users",
		"UPDATE tenants SET require_device_attestation = 0",
		"SET FOREIGN_KEY_CHECKS=1",
	}
	for _, s := range stmts {
		if _, err := db.Exec(s); err != nil {
			t.Fatalf("reset (%s): %v", s, err)
		}
	}
}

func seedUser(t *testing.T, db *sql.DB) domain.ID {
	t.Helper()
	uid := domain.NewID()
	_, err := db.Exec(`
		INSERT INTO users (id, tenant_id, kc_subject, email, display_name)
		VALUES (?, ?, ?, ?, ?)`,
		uid.Bytes(), defaultTenantID().Bytes(),
		"kc-allowlist-"+uid.String(),
		"allow-"+uid.String()+"@example.com",
		"allowlist-test-user")
	if err != nil {
		t.Fatalf("seed user: %v", err)
	}
	return uid
}

// --- shared synthetic chain helper (mirrors the one in attestation_test) ---

func buildKeyDescription(t *testing.T, challenge []byte, secLevel int) []byte {
	t.Helper()
	emptyAuth, _ := asn1.Marshal(struct{}{})
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
	der, _ := asn1.Marshal(desc)
	return der
}

func buildSyntheticChain(t *testing.T, challenge []byte) (chainPEM, rootPEM []byte, leafCert *x509.Certificate) {
	t.Helper()
	rootKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rootTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "synthetic root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	rootDER, _ := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	rootCert, _ := x509.ParseCertificate(rootDER)

	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "leaf"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtraExtensions: []pkix.Extension{{
			Id:    attestation.AttestationOID,
			Value: buildKeyDescription(t, challenge, 1),
		}},
	}
	leafDER, _ := x509.CreateCertificate(rand.Reader, leafTmpl, rootCert, &leafKey.PublicKey, rootKey)
	leafCert, _ = x509.ParseCertificate(leafDER)

	chainPEM = append(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER})...,
	)
	rootPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER})
	return
}

// makeService builds an allowlist.Service backed by the test DB and a
// verifier whose root pool matches the synthetic chain we just built.
func makeService(t *testing.T, db *sql.DB, rootPEM []byte) *Service {
	t.Helper()
	v := attestation.New(attestation.WithRoots(rootPEM))
	s, err := New(Config{DB: db, Verifier: v})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return s
}

func TestIssueChallenge_Persists(t *testing.T) {
	db := requireTestDB(t)
	resetDB(t, db)
	uid := seedUser(t, db)

	_, root, _ := buildSyntheticChain(t, []byte("dummy-32-bytes-aaaaaaaaaaaaaaaaa"))
	svc := makeService(t, db, root)

	chal, err := svc.IssueChallenge(context.Background(), defaultTenantID(), uid)
	if err != nil {
		t.Fatalf("IssueChallenge: %v", err)
	}
	if len(chal) != attestation.ChallengeBytes {
		t.Errorf("challenge length: %d", len(chal))
	}
	var n int
	_ = db.QueryRow(`SELECT COUNT(*) FROM attestation_challenges WHERE user_id = ?`,
		uid.Bytes()).Scan(&n)
	if n != 1 {
		t.Errorf("challenge not persisted: rows=%d", n)
	}
}

func TestVerifyAndConsume_HappyPath_NoAllowlist(t *testing.T) {
	db := requireTestDB(t)
	resetDB(t, db)
	uid := seedUser(t, db)

	// Issue first to fix the challenge bytes the synthetic cert will
	// embed.
	chal := make([]byte, 32)
	for i := range chal {
		chal[i] = byte(i)
	}
	chain, root, _ := buildSyntheticChain(t, chal)
	svc := makeService(t, db, root)

	// Manually insert the challenge so the cert's embedded value matches.
	_, err := db.Exec(`INSERT INTO attestation_challenges (challenge, tenant_id, user_id) VALUES (?, ?, ?)`,
		chal, defaultTenantID().Bytes(), uid.Bytes())
	if err != nil {
		t.Fatalf("insert challenge: %v", err)
	}

	res, err := svc.VerifyAndConsume(context.Background(), defaultTenantID(), uid, chain)
	if err != nil {
		t.Fatalf("VerifyAndConsume: %v", err)
	}
	if res == nil || len(res.Fingerprint) != 32 {
		t.Fatal("missing fingerprint")
	}
}

func TestVerifyAndConsume_RejectsConsumedChallenge(t *testing.T) {
	db := requireTestDB(t)
	resetDB(t, db)
	uid := seedUser(t, db)

	chal := make([]byte, 32)
	for i := range chal {
		chal[i] = byte(i + 1)
	}
	chain, root, _ := buildSyntheticChain(t, chal)
	svc := makeService(t, db, root)

	_, _ = db.Exec(`INSERT INTO attestation_challenges (challenge, tenant_id, user_id, consumed_at) VALUES (?, ?, ?, NOW(6))`,
		chal, defaultTenantID().Bytes(), uid.Bytes())

	_, err := svc.VerifyAndConsume(context.Background(), defaultTenantID(), uid, chain)
	if !errors.Is(err, ErrChallengeConsumed) {
		t.Errorf("got %v, want ErrChallengeConsumed", err)
	}
}

func TestVerifyAndConsume_AllowlistMode_RejectsUnenrolled(t *testing.T) {
	db := requireTestDB(t)
	resetDB(t, db)
	uid := seedUser(t, db)

	// Turn on allowlist enforcement.
	_, _ = db.Exec(`UPDATE tenants SET require_device_attestation = 1 WHERE id = ?`,
		defaultTenantID().Bytes())

	chal := make([]byte, 32)
	for i := range chal {
		chal[i] = byte(0xA0 + i)
	}
	chain, root, _ := buildSyntheticChain(t, chal)
	svc := makeService(t, db, root)

	_, _ = db.Exec(`INSERT INTO attestation_challenges (challenge, tenant_id, user_id) VALUES (?, ?, ?)`,
		chal, defaultTenantID().Bytes(), uid.Bytes())

	_, err := svc.VerifyAndConsume(context.Background(), defaultTenantID(), uid, chain)
	if !errors.Is(err, ErrNotEnrolled) {
		t.Errorf("got %v, want ErrNotEnrolled", err)
	}

	// Even though the allowlist check failed, the challenge should now
	// be marked consumed (you can't probe by retrying).
	var consumedAt sql.NullTime
	_ = db.QueryRow(`SELECT consumed_at FROM attestation_challenges WHERE challenge = ?`,
		chal).Scan(&consumedAt)
	if !consumedAt.Valid {
		t.Error("challenge should be consumed even after allowlist rejection")
	}
}

func TestVerifyAndConsume_AllowlistMode_AcceptsEnrolled(t *testing.T) {
	db := requireTestDB(t)
	resetDB(t, db)
	uid := seedUser(t, db)
	_, _ = db.Exec(`UPDATE tenants SET require_device_attestation = 1 WHERE id = ?`,
		defaultTenantID().Bytes())

	chal := make([]byte, 32)
	for i := range chal {
		chal[i] = byte(0xC0 + i)
	}
	chain, root, leaf := buildSyntheticChain(t, chal)
	svc := makeService(t, db, root)

	// Pre-compute the fingerprint and enrol it.
	der, _ := x509.MarshalPKIXPublicKey(leaf.PublicKey)
	fp := sha256.Sum256(der)
	if err := svc.Enroll(context.Background(), defaultTenantID(), fp[:], "alice's pixel", nil); err != nil {
		t.Fatalf("Enroll: %v", err)
	}

	_, _ = db.Exec(`INSERT INTO attestation_challenges (challenge, tenant_id, user_id) VALUES (?, ?, ?)`,
		chal, defaultTenantID().Bytes(), uid.Bytes())

	res, err := svc.VerifyAndConsume(context.Background(), defaultTenantID(), uid, chain)
	if err != nil {
		t.Fatalf("VerifyAndConsume: %v", err)
	}
	if res.Fingerprint != fp {
		t.Error("verification did not return the enrolled fingerprint")
	}
}

func TestEnrollAndList_Roundtrip(t *testing.T) {
	db := requireTestDB(t)
	resetDB(t, db)
	_, root, _ := buildSyntheticChain(t, []byte("0000000000000000000000000000abcd"))
	svc := makeService(t, db, root)

	fp := make([]byte, 32)
	for i := range fp {
		fp[i] = byte(i)
	}
	if err := svc.Enroll(context.Background(), defaultTenantID(), fp, "test device", nil); err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	list, err := svc.List(context.Background(), defaultTenantID())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list) != 1 || list[0].Label != "test device" {
		t.Errorf("list mismatch: %+v", list)
	}

	// Re-enrol with same fingerprint should update label, not duplicate.
	if err := svc.Enroll(context.Background(), defaultTenantID(), fp, "renamed", nil); err != nil {
		t.Fatalf("re-Enroll: %v", err)
	}
	list2, _ := svc.List(context.Background(), defaultTenantID())
	if len(list2) != 1 || list2[0].Label != "renamed" {
		t.Errorf("re-enrol failed: %+v", list2)
	}

	// Revoke removes from list.
	if err := svc.Revoke(context.Background(), defaultTenantID(), fp); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	list3, _ := svc.List(context.Background(), defaultTenantID())
	if len(list3) != 0 {
		t.Errorf("revoked entry still present: %+v", list3)
	}
}

func TestSetTenantRequireAllowlist(t *testing.T) {
	db := requireTestDB(t)
	resetDB(t, db)
	_, root, _ := buildSyntheticChain(t, []byte("0000000000000000000000000000abcd"))
	svc := makeService(t, db, root)

	if err := svc.SetTenantRequireAllowlist(context.Background(), defaultTenantID(), true); err != nil {
		t.Fatalf("set on: %v", err)
	}
	var v int
	_ = db.QueryRow(`SELECT require_device_attestation FROM tenants WHERE id = ?`,
		defaultTenantID().Bytes()).Scan(&v)
	if v != 1 {
		t.Errorf("flag = %d, want 1", v)
	}

	if err := svc.SetTenantRequireAllowlist(context.Background(), defaultTenantID(), false); err != nil {
		t.Fatalf("set off: %v", err)
	}
	_ = db.QueryRow(`SELECT require_device_attestation FROM tenants WHERE id = ?`,
		defaultTenantID().Bytes()).Scan(&v)
	if v != 0 {
		t.Errorf("flag = %d, want 0", v)
	}
}

// (helpers above; tests above use sha256.Sum256 directly)
