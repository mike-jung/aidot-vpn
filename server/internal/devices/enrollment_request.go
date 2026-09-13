package devices

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"database/sql"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"github.com/aidotvpn/server/internal/domain"
)

// Device-initiated enrollment, approved by an admin.
//
// The console used to mint a token that somebody then had to get onto a
// phone. Thirty-eight characters, no channel to send them, and mailing a
// bearer credential around is worse than the problem. Reversing the
// direction removes the transfer entirely: the phone asks, the admin
// approves.
//
// Security rests on the approval step, not the shared password. Knowing
// the password gets a request into a queue; an admin still has to look
// at it and confirm the six digits on the handset match the six digits
// in the row. That comparison is what binds a database record to a
// physical device, and it is the same construction as Bluetooth numeric
// comparison — where the passkey is not secret either.

// EnrollmentRequest is a pending or decided enrolment.
type EnrollmentRequest struct {
	ID               domain.ID
	TenantID         domain.ID
	InstallID        string
	DisplayName      string
	Platform         string
	DevicePublicKey  string
	VerificationCode string
	Status           string
	PolicyID         *domain.ID
	DeviceID         *domain.ID
	ExpiresAt        time.Time
	DecidedAt        *time.Time
	CreatedAt        time.Time
}

var (
	// ErrEnrollPassword is returned for a wrong shared password.
	ErrEnrollPassword = errors.New("등록 비밀번호가 올바르지 않습니다")

	// ErrRequestNotPending covers approved, rejected, expired and
	// unknown alike — one error, for the same reason the token path has
	// one: an unauthenticated caller learns only that it cannot proceed.
	ErrRequestNotPending = errors.New("처리할 수 없는 등록 요청입니다")
)

// enrollmentRequestTTL bounds how long a request waits for a decision.
//
// Ten minutes. Long enough to walk a handset to whoever has the console,
// short enough that a queue left open overnight is empty by morning —
// and short enough that guessing a six-digit code has to happen inside
// it.
const enrollmentRequestTTL = 10 * time.Minute

// newVerificationCode returns six digits, uniformly distributed.
//
// Read aloud, so digits rather than base64: "428913" survives a noisy
// ward and a phone speaker; "aidot_u_Yhbc" does not.
func newVerificationCode() (string, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	// Modulo on a 64-bit draw: the bias against 10^6 is about 1 in 10^13,
	// which is not a consideration here and keeps this branch-free.
	return fmt.Sprintf("%06d", binary.BigEndian.Uint64(b[:])%1_000_000), nil
}

// CreateEnrollmentRequest records a device's request to enrol.
//
// The password is compared in constant time. It is a shared secret, so
// timing does not reveal much, but a comparison that leaks length or
// prefix is free to avoid and someone will copy this function.
func (s *Service) CreateEnrollmentRequest(
	ctx context.Context,
	tenantID domain.ID,
	sharedPassword, suppliedPassword string,
	installID, displayName, platform, devicePublicKey string,
) (*EnrollmentRequest, error) {
	if tenantID.IsZero() {
		tenantID = s.tenantID
	}
	if sharedPassword == "" {
		return nil, errors.New("서버에 등록 비밀번호가 설정되지 않았습니다")
	}
	if subtle.ConstantTimeCompare([]byte(sharedPassword), []byte(suppliedPassword)) != 1 {
		return nil, ErrEnrollPassword
	}
	if installID == "" || devicePublicKey == "" {
		return nil, errors.New("install_id 와 device_public_key 가 필요합니다")
	}
	if err := validateInstallID(installID); err != nil {
		return nil, err
	}
	if displayName == "" {
		displayName = "이름 없는 기기"
	}
	if platform == "" {
		platform = "android"
	}

	code, err := newVerificationCode()
	if err != nil {
		return nil, fmt.Errorf("CreateEnrollmentRequest: entropy: %w", err)
	}

	req := &EnrollmentRequest{
		ID:               domain.NewID(),
		TenantID:         tenantID,
		InstallID:        installID,
		DisplayName:      displayName,
		Platform:         platform,
		DevicePublicKey:  devicePublicKey,
		VerificationCode: code,
		Status:           "pending",
		ExpiresAt:        time.Now().UTC().Add(enrollmentRequestTTL),
		CreatedAt:        time.Now().UTC(),
	}

	// Supersede any earlier pending request from the same install.
	//
	// Without this, tapping the button twice leaves two rows with
	// different codes and the admin cannot tell which the phone is
	// showing — the one thing the code exists to make unambiguous.
	if _, err := s.db.ExecContext(ctx, `
		UPDATE enrollment_requests
		SET status = 'rejected', decided_at = CURRENT_TIMESTAMP(6)
		WHERE tenant_id = ? AND install_id = ? AND status = 'pending'`,
		tenantID.Bytes(), installID); err != nil {
		return nil, fmt.Errorf("CreateEnrollmentRequest: supersede: %w", err)
	}

	if _, err := s.db.ExecContext(ctx, `
		INSERT INTO enrollment_requests
		  (id, tenant_id, install_id, display_name, platform,
		   device_public_key, verification_code, expires_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		req.ID.Bytes(), tenantID.Bytes(), installID, displayName, platform,
		devicePublicKey, code, req.ExpiresAt); err != nil {
		return nil, fmt.Errorf("CreateEnrollmentRequest: %w", err)
	}
	return req, nil
}

func scanEnrollmentRequest(sc interface{ Scan(...any) error }) (*EnrollmentRequest, error) {
	var (
		r                     EnrollmentRequest
		idB, tenB, polB, devB []byte
		decided               sql.NullTime
	)
	if err := sc.Scan(&idB, &tenB, &r.InstallID, &r.DisplayName, &r.Platform,
		&r.DevicePublicKey, &r.VerificationCode, &r.Status, &polB, &devB,
		&r.ExpiresAt, &decided, &r.CreatedAt); err != nil {
		return nil, err
	}
	_ = r.ID.Scan(idB)
	_ = r.TenantID.Scan(tenB)
	if len(polB) > 0 {
		var p domain.ID
		if p.Scan(polB) == nil {
			r.PolicyID = &p
		}
	}
	if len(devB) > 0 {
		var d domain.ID
		if d.Scan(devB) == nil {
			r.DeviceID = &d
		}
	}
	if decided.Valid {
		t := decided.Time
		r.DecidedAt = &t
	}
	return &r, nil
}

const enrollmentRequestCols = `
	id, tenant_id, install_id, display_name, platform,
	device_public_key, verification_code, status, policy_id, device_id,
	expires_at, decided_at, created_at`

// GetEnrollmentRequest returns one request by id. Used by the phone's
// poll, so it takes no tenant — the id is unguessable and the response
// carries nothing an attacker gains from.
func (s *Service) GetEnrollmentRequest(ctx context.Context, id domain.ID) (*EnrollmentRequest, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT `+enrollmentRequestCols+` FROM enrollment_requests WHERE id = ?`,
		id.Bytes())
	r, err := scanEnrollmentRequest(row)
	if err != nil {
		return nil, ErrRequestNotPending
	}
	return r, nil
}

// ListEnrollmentRequests returns a tenant's requests, newest first.
func (s *Service) ListEnrollmentRequests(ctx context.Context, tenantID domain.ID) ([]EnrollmentRequest, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT `+enrollmentRequestCols+`
		 FROM enrollment_requests WHERE tenant_id = ?
		 ORDER BY created_at DESC LIMIT 100`, tenantID.Bytes())
	if err != nil {
		return nil, fmt.Errorf("ListEnrollmentRequests: %w", err)
	}
	defer rows.Close()

	var out []EnrollmentRequest
	for rows.Next() {
		r, err := scanEnrollmentRequest(rows)
		if err != nil {
			return nil, fmt.Errorf("ListEnrollmentRequests: %w", err)
		}
		out = append(out, *r)
	}
	return out, rows.Err()
}

// MarkApprovedWithGrant records approval and parks the one-time token
// the device collects on its next poll.
func (s *Service) MarkApprovedWithGrant(ctx context.Context, id, decidedBy domain.ID, policyID *domain.ID, grant string) error {
	var pol any
	if policyID != nil {
		pol = policyID.Bytes()
	}
	res, err := s.db.ExecContext(ctx, `
		UPDATE enrollment_requests
		SET status = 'approved', policy_id = ?, grant_token = ?,
		    decided_at = CURRENT_TIMESTAMP(6), decided_by = ?
		WHERE id = ? AND status = 'pending' AND expires_at > CURRENT_TIMESTAMP(6)`,
		pol, grant, decidedBy.Bytes(), id.Bytes())
	if err != nil {
		return fmt.Errorf("MarkApprovedWithGrant: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrRequestNotPending
	}
	return nil
}

// TakeGrant returns the parked token and clears it, atomically.
//
// UPDATE-then-SELECT rather than the reverse: two phones polling the
// same id must not both receive it, and the row lock in the UPDATE is
// what makes that true.
func (s *Service) TakeGrant(ctx context.Context, id domain.ID) (string, error) {
	var grant sql.NullString
	if err := s.db.QueryRowContext(ctx,
		`SELECT grant_token FROM enrollment_requests WHERE id = ?`,
		id.Bytes()).Scan(&grant); err != nil {
		return "", err
	}
	if !grant.Valid || grant.String == "" {
		return "", nil
	}
	res, err := s.db.ExecContext(ctx,
		`UPDATE enrollment_requests SET grant_token = NULL
		 WHERE id = ? AND grant_token = ?`, id.Bytes(), grant.String)
	if err != nil {
		return "", err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		// Someone else took it between the read and the clear.
		return "", nil
	}
	return grant.String, nil
}

// MarkApproved records the decision and the device it produced.
//
// The device itself is created by the caller through the normal
// Register path — approval decides, it does not become a second way to
// make a device.
func (s *Service) MarkApproved(ctx context.Context, id, deviceID, decidedBy domain.ID, policyID *domain.ID) error {
	var pol any
	if policyID != nil {
		pol = policyID.Bytes()
	}
	res, err := s.db.ExecContext(ctx, `
		UPDATE enrollment_requests
		SET status = 'approved', device_id = ?, policy_id = ?,
		    decided_at = CURRENT_TIMESTAMP(6), decided_by = ?
		WHERE id = ? AND status = 'pending' AND expires_at > CURRENT_TIMESTAMP(6)`,
		deviceID.Bytes(), pol, decidedBy.Bytes(), id.Bytes())
	if err != nil {
		return fmt.Errorf("MarkApproved: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrRequestNotPending
	}
	return nil
}

// RejectEnrollmentRequest declines a pending request.
func (s *Service) RejectEnrollmentRequest(ctx context.Context, tenantID, id, decidedBy domain.ID) error {
	res, err := s.db.ExecContext(ctx, `
		UPDATE enrollment_requests
		SET status = 'rejected', decided_at = CURRENT_TIMESTAMP(6), decided_by = ?
		WHERE id = ? AND tenant_id = ? AND status = 'pending'`,
		decidedBy.Bytes(), id.Bytes(), tenantID.Bytes())
	if err != nil {
		return fmt.Errorf("RejectEnrollmentRequest: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrRequestNotPending
	}
	return nil
}

// Pending reports whether a request may still be decided.
func (r *EnrollmentRequest) Pending(now time.Time) bool {
	return r.Status == "pending" && now.Before(r.ExpiresAt)
}
