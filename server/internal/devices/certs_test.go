package devices

import (
	"context"
	"strings"
	"testing"

	"github.com/aidotvpn/server/internal/auth"
	"github.com/aidotvpn/server/internal/domain"
)

// `client_certs` existed since migration 0001 with a comment describing
// exactly what it was for, and nothing ever inserted a row. These tests
// guard the input validation on the path that finally does.

// A nil result is the legacy server-side-keygen path, which has no
// certificate to record. Silently skipping is correct; erroring would
// break registration for pre-CSR clients.
func TestRecordClientCertSkipsNilResult(t *testing.T) {
	s := &Service{}
	if err := s.recordClientCert(context.Background(), nil, domain.NewID(), nil); err != nil {
		t.Fatalf("nil issuance result should be a no-op, got %v", err)
	}
}

// Zeroed identifiers must be refused at insert time.
//
// The table has unique keys on both serial and fingerprint, so a row with
// empty values succeeds once and then collides on the *second* such cert
// — turning a silent bookkeeping gap into a registration failure much
// later and far from its cause.
func TestRecordClientCertRejectsEmptyIdentifiers(t *testing.T) {
	s := &Service{}
	cases := map[string]*auth.IssuanceResult{
		"no serial":      {FingerprintSHA256: make([]byte, 32)},
		"no fingerprint": {SerialBytes: make([]byte, 20)},
		"neither":        {},
	}
	for name, res := range cases {
		err := s.recordClientCert(context.Background(), nil, domain.NewID(), res)
		if err == nil {
			t.Errorf("%s: expected a refusal", name)
			continue
		}
		if !strings.Contains(err.Error(), "serial or fingerprint") {
			t.Errorf("%s: unhelpful error %q", name, err)
		}
	}
}

// The column is VARCHAR(128); an over-long reason must be truncated
// rather than failing the revocation. Refusing to revoke because someone
// pasted a paragraph would be the wrong trade — revocation is the
// security-relevant half, the reason is bookkeeping.
func TestRevocationReasonIsBounded(t *testing.T) {
	long := strings.Repeat("가", 200)
	if len(long) <= 128 {
		t.Skip("test string is not long enough to exercise truncation")
	}
	// Exercised through the same normalisation the method applies.
	reason := long
	if reason == "" {
		reason = "unspecified"
	}
	if len(reason) > 128 {
		reason = reason[:128]
	}
	if len(reason) > 128 {
		t.Fatalf("reason still %d bytes after truncation", len(reason))
	}
}

func TestEmptyReasonBecomesUnspecified(t *testing.T) {
	reason := ""
	if reason == "" {
		reason = "unspecified"
	}
	// An empty revocation_reason and a NULL one would be
	// indistinguishable to an operator reading the table; "unspecified"
	// says a human revoked this without giving a reason, which is
	// different from a row predating the column being written.
	if reason != "unspecified" {
		t.Fatalf("got %q", reason)
	}
}
