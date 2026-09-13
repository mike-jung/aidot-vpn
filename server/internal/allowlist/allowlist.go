// Package allowlist gates device registration on a pre-enrolled list of
// hardware-attested device fingerprints.
//
// This is the optional "registered devices only" mode the AidotVpn admin
// can flip per tenant. When enabled:
//
//  1. Client requests an attestation challenge (32-byte server nonce).
//  2. Client embeds the challenge in its Keystore-generated EC key.
//  3. Client uploads the resulting attestation cert chain alongside CSR.
//  4. Controller verifies the chain (see internal/attestation).
//  5. Controller computes the fingerprint and checks it against
//     device_attestations_allowlist for the tenant.
//  6. Reject if not enrolled; otherwise proceed with Register.
//
// When disabled (the default), the chain is still verified but no
// allowlist check happens — every successfully attested device is
// allowed to register.
package allowlist

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/aidotvpn/server/internal/attestation"
	"github.com/aidotvpn/server/internal/domain"
)

// Errors callers should distinguish.
var (
	ErrNotEnrolled       = errors.New("allowlist: device not in tenant allowlist")
	ErrUnknownChallenge  = errors.New("allowlist: unknown attestation challenge")
	ErrChallengeConsumed = errors.New("allowlist: attestation challenge already consumed")
	ErrChallengeExpired  = errors.New("allowlist: attestation challenge expired")
)

// ChallengeTTL caps how long a server-issued attestation challenge stays
// valid. Five minutes is generous for a Register flow that involves
// Keystore key generation + a network round trip.
const ChallengeTTL = 5 * time.Minute

// Service composes the challenge issuance + allowlist enforcement
// surface. It is transport-agnostic — Connect handlers delegate here.
type Service struct {
	db       *sql.DB
	verifier *attestation.Verifier
	now      func() time.Time
}

type Config struct {
	DB       *sql.DB
	Verifier *attestation.Verifier
	Now      func() time.Time
}

func New(cfg Config) (*Service, error) {
	if cfg.DB == nil {
		return nil, errors.New("allowlist.New: DB is required")
	}
	if cfg.Verifier == nil {
		return nil, errors.New("allowlist.New: Verifier is required")
	}
	s := &Service{db: cfg.DB, verifier: cfg.Verifier, now: cfg.Now}
	if s.now == nil {
		s.now = func() time.Time { return time.Now().UTC() }
	}
	return s, nil
}

// IssueChallenge produces a fresh 32-byte attestation challenge and
// records it in [attestation_challenges]. Returns the bytes the client
// should pass to KeyGenParameterSpec.setAttestationChallenge.
func (s *Service) IssueChallenge(ctx context.Context, tenantID, userID domain.ID) ([]byte, error) {
	if tenantID.IsZero() || userID.IsZero() {
		return nil, errors.New("IssueChallenge: tenant + user required")
	}
	chal := make([]byte, attestation.ChallengeBytes)
	if _, err := rand.Read(chal); err != nil {
		return nil, fmt.Errorf("rand: %w", err)
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO attestation_challenges
		  (challenge, tenant_id, user_id, issued_at)
		VALUES (?, ?, ?, NOW(6))`,
		chal, tenantID.Bytes(), userID.Bytes())
	if err != nil {
		return nil, fmt.Errorf("insert challenge: %w", err)
	}
	return chal, nil
}

// VerifyAndConsume validates an attestation chain against a previously
// issued challenge, marks the challenge consumed (so it can't be
// replayed), and — if the tenant has require_device_attestation enabled —
// checks the resulting fingerprint against the allowlist.
//
// Returns the verified attestation result. The caller persists this to
// attestation_records as part of Register.
func (s *Service) VerifyAndConsume(
	ctx context.Context,
	tenantID, userID domain.ID,
	chainPEM []byte,
) (*attestation.Result, error) {

	// 1. Look up the challenge for this user. We look up by (user_id,
	//    consumed_at IS NULL) and verify the chain emits the same bytes.
	row := s.db.QueryRowContext(ctx, `
		SELECT challenge, issued_at, consumed_at
		FROM attestation_challenges
		WHERE user_id = ?
		ORDER BY issued_at DESC
		LIMIT 1`, userID.Bytes())
	var (
		chal       []byte
		issuedAt   time.Time
		consumedAt sql.NullTime
	)
	if err := row.Scan(&chal, &issuedAt, &consumedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrUnknownChallenge
		}
		return nil, fmt.Errorf("look up challenge: %w", err)
	}
	if consumedAt.Valid {
		return nil, ErrChallengeConsumed
	}
	if s.now().Sub(issuedAt) > ChallengeTTL {
		return nil, ErrChallengeExpired
	}

	// 2. Verify the chain.
	res, err := s.verifier.VerifyChain(chainPEM, chal)
	if err != nil {
		return nil, fmt.Errorf("attestation verify: %w", err)
	}

	// 3. Mark the challenge consumed before any allowlist check — even a
	//    failed allowlist check should burn the challenge so attackers
	//    can't probe the allowlist with a single nonce.
	if _, err := s.db.ExecContext(ctx, `
		UPDATE attestation_challenges SET consumed_at = NOW(6)
		WHERE challenge = ?`, chal); err != nil {
		return nil, fmt.Errorf("mark consumed: %w", err)
	}

	// 4. Allowlist enforcement (if enabled for the tenant).
	if requireAllowlist, err := s.tenantRequiresAllowlist(ctx, tenantID); err != nil {
		return nil, err
	} else if requireAllowlist {
		ok, err := s.fingerprintEnrolled(ctx, tenantID, res.Fingerprint[:])
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, ErrNotEnrolled
		}
	}
	return res, nil
}

// Enroll adds a fingerprint to a tenant's allowlist. Idempotent — calling
// twice with the same fingerprint replaces the label.
func (s *Service) Enroll(ctx context.Context, tenantID domain.ID, fingerprint []byte, label string, enrolledBy *domain.ID) error {
	if len(fingerprint) != 32 {
		return fmt.Errorf("Enroll: fingerprint must be 32 bytes, got %d", len(fingerprint))
	}
	id := domain.NewID()
	var enrolledByArg any
	if enrolledBy != nil {
		enrolledByArg = enrolledBy.Bytes()
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO device_attestations_allowlist
		  (id, tenant_id, fingerprint, label, enrolled_by)
		VALUES (?, ?, ?, ?, ?)
		ON DUPLICATE KEY UPDATE
		  label = VALUES(label),
		  deleted_at = NULL`,
		id.Bytes(), tenantID.Bytes(), fingerprint, label, enrolledByArg)
	if err != nil {
		return fmt.Errorf("enroll: %w", err)
	}
	return nil
}

// Revoke soft-deletes a fingerprint from the allowlist. Devices already
// registered remain registered; only future Register calls are affected.
func (s *Service) Revoke(ctx context.Context, tenantID domain.ID, fingerprint []byte) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE device_attestations_allowlist
		SET deleted_at = NOW(6)
		WHERE tenant_id = ? AND fingerprint = ? AND deleted_at IS NULL`,
		tenantID.Bytes(), fingerprint)
	return err
}

// EnrolledFingerprint is the row shape List returns.
type EnrolledFingerprint struct {
	Fingerprint []byte
	Label       string
	EnrolledAt  time.Time
}

// List returns all enrolled fingerprints for a tenant, newest first.
func (s *Service) List(ctx context.Context, tenantID domain.ID) ([]EnrolledFingerprint, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT fingerprint, label, enrolled_at
		FROM device_attestations_allowlist
		WHERE tenant_id = ? AND deleted_at IS NULL
		ORDER BY enrolled_at DESC`,
		tenantID.Bytes())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []EnrolledFingerprint
	for rows.Next() {
		var e EnrolledFingerprint
		if err := rows.Scan(&e.Fingerprint, &e.Label, &e.EnrolledAt); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// SetTenantRequireAllowlist toggles enforcement for a tenant.
// Called from the admin console.
func (s *Service) SetTenantRequireAllowlist(ctx context.Context, tenantID domain.ID, on bool) error {
	v := 0
	if on {
		v = 1
	}
	_, err := s.db.ExecContext(ctx, `
		UPDATE tenants SET require_device_attestation = ? WHERE id = ?`,
		v, tenantID.Bytes())
	return err
}

// --- internals ---------------------------------------------------------

func (s *Service) tenantRequiresAllowlist(ctx context.Context, tenantID domain.ID) (bool, error) {
	var v int
	row := s.db.QueryRowContext(ctx,
		`SELECT require_device_attestation FROM tenants WHERE id = ?`,
		tenantID.Bytes())
	if err := row.Scan(&v); err != nil {
		return false, fmt.Errorf("read tenant flag: %w", err)
	}
	return v != 0, nil
}

func (s *Service) fingerprintEnrolled(ctx context.Context, tenantID domain.ID, fp []byte) (bool, error) {
	var dummy int
	row := s.db.QueryRowContext(ctx, `
		SELECT 1
		FROM device_attestations_allowlist
		WHERE tenant_id = ? AND fingerprint = ? AND deleted_at IS NULL
		LIMIT 1`,
		tenantID.Bytes(), fp)
	if err := row.Scan(&dummy); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// CurrentChallengeB64 returns the user's outstanding attestation
// challenge, base64-encoded exactly as the Android client embeds it in a
// Play Integrity request.
//
// Both gates read the SAME challenge on purpose. Key attestation binds it
// into the certificate; Play Integrity binds it into the token's nonce.
// Issuing two independent nonces would let an attacker replay one gate's
// evidence while satisfying the other freshly — binding both to one value
// means a replayed token fails against a challenge the live registration
// never used.
//
// Does NOT consume the challenge: VerifyAndConsume owns that, and burning
// it here would make whichever gate ran second fail against a nonce that
// no longer exists.
func (s *Service) CurrentChallengeB64(
	ctx context.Context,
	tenantID, userID domain.ID,
) (string, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT challenge, issued_at
		  FROM attestation_challenges
		 WHERE user_id = ? AND consumed_at IS NULL
		 ORDER BY issued_at DESC
		 LIMIT 1`, userID.Bytes())

	var (
		chal     []byte
		issuedAt time.Time
	)
	if err := row.Scan(&chal, &issuedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", ErrUnknownChallenge
		}
		return "", fmt.Errorf("look up challenge: %w", err)
	}
	if s.now().Sub(issuedAt) > ChallengeTTL {
		return "", ErrChallengeExpired
	}
	return base64.StdEncoding.EncodeToString(chal), nil
}
