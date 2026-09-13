package devices

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/aidotvpn/server/internal/domain"
)

// Enrollment tokens — a credential an operator can create by clicking,
// so enrolling a phone does not require a terminal.
//
// The previous path was: mint an OIDC access token with curl, paste it
// into the app. That works, and it asks an operator enrolling a nurse's
// handset for the realm's client id, a user's password, and a shell.
//
// The design follows what Android Management API, Elastic Fleet and
// Chrome Enterprise all settled on, because they were solving this same
// problem and arrived at the same answers:
//
//   - bound to a policy, so a device arrives governed rather than
//     registered-but-unreachable
//   - an expiry, because an enrolment credential that never expires is
//     one somebody finds in a chat log next year
//   - single or multi use, decided at creation
//   - revocable without touching the devices already enrolled with it
//
// ## Why this is not simply "a password for enrolment"
//
// It authorises exactly one operation, for a bounded time, with a
// bounded blast radius. An OIDC access token authorises everything its
// bearer can do, for as long as it lives. Pasting the latter into a
// handset — which is what the tutorial used to instruct — hands a phone
// the user's whole session.

// EnrollmentToken is the stored record. The secret itself is not here:
// only its SHA-256, matching how node agent tokens are kept.
type EnrollmentToken struct {
	ID        domain.ID
	TenantID  domain.ID
	Name      string
	PolicyID  *domain.ID
	MaxUses   int
	UsedCount int
	ExpiresAt time.Time
	RevokedAt *time.Time
	CreatedBy *domain.ID
	CreatedAt time.Time
}

// Status collapses the three ways a token can be unusable into one word
// for the console, so the UI does not re-derive the rule and drift.
func (t *EnrollmentToken) Status(now time.Time) string {
	switch {
	case t.RevokedAt != nil:
		return "revoked"
	case now.After(t.ExpiresAt):
		return "expired"
	case t.MaxUses > 0 && t.UsedCount >= t.MaxUses:
		return "used_up"
	default:
		return "active"
	}
}

var (
	// ErrTokenUnusable covers revoked, expired and exhausted alike.
	//
	// Deliberately one error. Telling an unauthenticated caller *which*
	// of the three applies confirms the token existed, which is a small
	// oracle and free to avoid.
	ErrTokenUnusable = errors.New("enrollment token is not usable")
)

// CreateEnrollmentToken returns the record and the plaintext secret.
//
// The secret is returned exactly once and never stored. A token that can
// be re-read from the database is one that leaks with the database.
func (s *Service) CreateEnrollmentToken(
	ctx context.Context,
	tenantID domain.ID,
	createdBy domain.ID,
	name string,
	policyID *domain.ID,
	maxUses int,
	ttl time.Duration,
) (*EnrollmentToken, string, error) {
	if tenantID.IsZero() {
		return nil, "", errors.New("CreateEnrollmentToken: tenantID is zero")
	}
	if name == "" {
		return nil, "", errors.New("이름을 입력하세요")
	}
	if maxUses < 0 {
		return nil, "", errors.New("사용 횟수는 0 이상이어야 합니다")
	}
	if ttl <= 0 {
		ttl = 24 * time.Hour
	}

	// 32 bytes, URL-safe, unpadded. Long enough that guessing is not a
	// consideration, short enough to read aloud over a phone if someone
	// has to.
	raw := make([]byte, 24)
	if _, err := rand.Read(raw); err != nil {
		return nil, "", fmt.Errorf("CreateEnrollmentToken: entropy: %w", err)
	}
	secret := "aidot_" + base64.RawURLEncoding.EncodeToString(raw)
	sum := sha256.Sum256([]byte(secret))

	tok := &EnrollmentToken{
		ID:        domain.NewID(),
		TenantID:  tenantID,
		Name:      name,
		PolicyID:  policyID,
		MaxUses:   maxUses,
		ExpiresAt: time.Now().UTC().Add(ttl),
		CreatedAt: time.Now().UTC(),
	}
	if !createdBy.IsZero() {
		tok.CreatedBy = &createdBy
	}

	var policyBytes any
	if policyID != nil {
		policyBytes = policyID.Bytes()
	}
	var byBytes any
	if tok.CreatedBy != nil {
		byBytes = tok.CreatedBy.Bytes()
	}

	_, err := s.db.ExecContext(ctx, `
		INSERT INTO enrollment_tokens
		  (id, tenant_id, name, token_hash, policy_id, max_uses, expires_at, created_by)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		tok.ID.Bytes(), tenantID.Bytes(), name, sum[:],
		policyBytes, maxUses, tok.ExpiresAt, byBytes)
	if err != nil {
		return nil, "", fmt.Errorf("CreateEnrollmentToken: %w", err)
	}
	return tok, secret, nil
}

// ListEnrollmentTokens returns a tenant's tokens, newest first.
func (s *Service) ListEnrollmentTokens(ctx context.Context, tenantID domain.ID) ([]EnrollmentToken, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, tenant_id, name, policy_id, max_uses, used_count,
		       expires_at, revoked_at, created_by, created_at
		FROM enrollment_tokens
		WHERE tenant_id = ?
		ORDER BY created_at DESC`, tenantID.Bytes())
	if err != nil {
		return nil, fmt.Errorf("ListEnrollmentTokens: %w", err)
	}
	defer rows.Close()

	var out []EnrollmentToken
	for rows.Next() {
		var (
			t         EnrollmentToken
			idB, tenB []byte
			polB, byB []byte
			revoked   sql.NullTime
		)
		if err := rows.Scan(&idB, &tenB, &t.Name, &polB, &t.MaxUses, &t.UsedCount,
			&t.ExpiresAt, &revoked, &byB, &t.CreatedAt); err != nil {
			return nil, fmt.Errorf("ListEnrollmentTokens: %w", err)
		}
		_ = t.ID.Scan(idB)
		_ = t.TenantID.Scan(tenB)
		if len(polB) > 0 {
			var p domain.ID
			if p.Scan(polB) == nil {
				t.PolicyID = &p
			}
		}
		if len(byB) > 0 {
			var u domain.ID
			if u.Scan(byB) == nil {
				t.CreatedBy = &u
			}
		}
		if revoked.Valid {
			rt := revoked.Time
			t.RevokedAt = &rt
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// RevokeEnrollmentToken stops further enrolments with this token.
//
// Devices already enrolled are untouched. Revoking is how you pause
// enrolment, and disconnecting everyone who used the token would make
// that a thing nobody dares do.
func (s *Service) RevokeEnrollmentToken(ctx context.Context, tenantID, id domain.ID) error {
	res, err := s.db.ExecContext(ctx, `
		UPDATE enrollment_tokens
		SET revoked_at = CURRENT_TIMESTAMP(6)
		WHERE id = ? AND tenant_id = ? AND revoked_at IS NULL`,
		id.Bytes(), tenantID.Bytes())
	if err != nil {
		return fmt.Errorf("RevokeEnrollmentToken: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return errors.New("토큰을 찾을 수 없거나 이미 폐기되었습니다")
	}
	return nil
}

// CheckEnrollmentToken validates a secret, consuming it only when asked.
//
// Registration is two HTTP calls and both present the same grant. Burning
// it on the first left the second unauthenticated, so validation and
// consumption are now separate decisions made by the caller.
//
// When consume is true this is exactly RedeemEnrollmentToken; when false
// it answers the same question without changing anything.
func (s *Service) CheckEnrollmentToken(ctx context.Context, secret string, consume bool) (domain.ID, *domain.ID, error) {
	if consume {
		return s.RedeemEnrollmentToken(ctx, secret)
	}

	sum := sha256.Sum256([]byte(secret))
	var tenB, polB []byte
	err := s.db.QueryRowContext(ctx, `
		SELECT tenant_id, policy_id FROM enrollment_tokens
		WHERE token_hash = ?
		  AND revoked_at IS NULL
		  AND expires_at > CURRENT_TIMESTAMP(6)
		  AND (max_uses = 0 OR used_count < max_uses)`, sum[:]).Scan(&tenB, &polB)
	if err != nil {
		return domain.ID{}, nil, ErrTokenUnusable
	}

	var tenantID domain.ID
	_ = tenantID.Scan(tenB)
	var policyID *domain.ID
	if len(polB) > 0 {
		var p domain.ID
		if p.Scan(polB) == nil {
			policyID = &p
		}
	}
	return tenantID, policyID, nil
}

// RedeemEnrollmentToken validates a secret and increments its use count.
//
// Returns the policy the enrolling device should be bound to. The
// increment and the check are one statement so two phones enrolling at
// the same moment cannot both take the last use of a single-use token.
func (s *Service) RedeemEnrollmentToken(ctx context.Context, secret string) (tenantID domain.ID, policyID *domain.ID, err error) {
	sum := sha256.Sum256([]byte(secret))

	res, err := s.db.ExecContext(ctx, `
		UPDATE enrollment_tokens
		SET used_count = used_count + 1
		WHERE token_hash = ?
		  AND revoked_at IS NULL
		  AND expires_at > CURRENT_TIMESTAMP(6)
		  AND (max_uses = 0 OR used_count < max_uses)`, sum[:])
	if err != nil {
		return domain.ID{}, nil, fmt.Errorf("RedeemEnrollmentToken: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return domain.ID{}, nil, ErrTokenUnusable
	}

	var tenB, polB []byte
	err = s.db.QueryRowContext(ctx, `
		SELECT tenant_id, policy_id FROM enrollment_tokens WHERE token_hash = ?`,
		sum[:]).Scan(&tenB, &polB)
	if err != nil {
		return domain.ID{}, nil, fmt.Errorf("RedeemEnrollmentToken: reread: %w", err)
	}
	_ = tenantID.Scan(tenB)
	if len(polB) > 0 {
		var p domain.ID
		if p.Scan(polB) == nil {
			policyID = &p
		}
	}
	return tenantID, policyID, nil
}
