// Package adminauth is console login without an identity server.
//
// Passwords: argon2id, OWASP's recommended parameters (64 MiB, 3 passes,
// 4 lanes), stored as a PHC string so the parameters travel with the
// hash and can be raised later without a migration.
//
// Sessions: a 32-byte random token in an HttpOnly cookie; the server
// stores only its SHA-256. Sliding expiry — thirty minutes idle, thirty
// days absolute. Logout deletes the row.
//
// Nothing here is novel. That is the point: the risk in home-grown auth
// is home-grown crypto, and there is none. See docs/auth-design-ko.md.
package adminauth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/aidotvpn/server/internal/domain"
	"golang.org/x/crypto/argon2"
)

const (
	// Thirty minutes idle.
	//
	// Eight hours was chosen for a developer's convenience and is wrong
	// for this console: the realistic threat is not a stolen cookie but
	// an unattended browser on a ward workstation, and eight hours means
	// a session survives a whole shift after someone walks away. Thirty
	// minutes is the common floor for administrative consoles handling
	// patient-adjacent systems.
	IdleTimeout     = 30 * time.Minute
	AbsoluteTimeout = 30 * 24 * time.Hour
	MaxFailedLogins = 5
	LockoutDuration = 15 * time.Minute

	argonTime    = 3
	argonMemory  = 64 * 1024
	argonThreads = 4
	argonKeyLen  = 32
)

var (
	ErrBadCredentials = errors.New("이메일 또는 비밀번호가 맞지 않습니다")
	ErrLocked         = errors.New("로그인 실패가 반복되어 잠시 잠겼습니다. 15분 뒤 다시 시도하세요")
	ErrDisabled       = errors.New("사용 중지된 계정입니다")
	ErrNoSession      = errors.New("no session")
)

type Admin struct {
	ID          domain.ID
	TenantID    domain.ID
	Email       string
	DisplayName string
	Role        string
	MustChange  bool
}

type Session struct {
	ID         domain.ID
	AdminID    domain.ID
	CreatedAt  time.Time
	LastUsedAt time.Time
	ExpiresAt  time.Time
	UserAgent  string
	IP         string
}

type Service struct {
	db *sql.DB
}

func New(db *sql.DB) *Service { return &Service{db: db} }

// ---------------------------------------------------------------- hashing

// HashPassword returns a PHC-format argon2id string.
func HashPassword(password string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",
		argonMemory, argonTime, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key)), nil
}

// VerifyPassword compares in constant time, reading the parameters from
// the stored string so old hashes keep verifying after a parameter bump.
func VerifyPassword(phc, password string) bool {
	parts := strings.Split(phc, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false
	}
	var m, t uint32
	var p uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &m, &t, &p); err != nil {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false
	}
	got := argon2.IDKey([]byte(password), salt, t, m, p, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1
}

// ---------------------------------------------------------------- admins

func (s *Service) Create(ctx context.Context, tenant domain.ID, email, name, password, role string, mustChange bool) (*Admin, error) {
	hash, err := HashPassword(password)
	if err != nil {
		return nil, err
	}
	id := domain.NewID()
	if _, err := s.db.ExecContext(ctx, `
		INSERT INTO admins (id, tenant_id, email, display_name, password_hash, role, must_change)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		id.Bytes(), tenant.Bytes(), strings.ToLower(strings.TrimSpace(email)), name, hash, role, mustChange); err != nil {
		return nil, fmt.Errorf("adminauth.Create: %w", err)
	}
	return &Admin{ID: id, TenantID: tenant, Email: email, DisplayName: name, Role: role, MustChange: mustChange}, nil
}

// Exists reports whether an admin with this email is on file.
func (s *Service) Exists(ctx context.Context, email string) (bool, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM admins WHERE email = ?`,
		strings.ToLower(strings.TrimSpace(email))).Scan(&n)
	return n > 0, err
}

func (s *Service) Count(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM admins`).Scan(&n)
	return n, err
}

// Login verifies credentials, enforces lockout, and opens a session.
// Returns the raw session token, which goes into the cookie and nowhere
// else.
// TOTPRequired reports whether this account has two-factor enabled.
func (s *Service) TOTPRequired(ctx context.Context, email string) (bool, string) {
	var secret sql.NullString
	var enabled sql.NullTime
	err := s.db.QueryRowContext(ctx,
		`SELECT totp_secret, totp_enabled_at FROM admins WHERE email = ?`,
		email).Scan(&secret, &enabled)
	if err != nil || !enabled.Valid || !secret.Valid {
		return false, ""
	}
	return true, secret.String
}

// ConsumeRecoveryCode spends one recovery code, if it matches.
//
// Marked used rather than deleted: an admin who finds a code already
// spent needs to know it happened, and a row with a timestamp says so
// where a missing row says nothing.
func (s *Service) ConsumeRecoveryCode(ctx context.Context, email, code string) bool {
	rows, err := s.db.QueryContext(ctx, `
		SELECT r.id, r.code_hash FROM admin_recovery_codes r
		  JOIN admins a ON a.id = r.admin_id
		 WHERE a.email = ? AND r.used_at IS NULL`, email)
	if err != nil {
		return false
	}
	defer rows.Close()
	for rows.Next() {
		var id []byte
		var hash string
		if rows.Scan(&id, &hash) != nil {
			continue
		}
		if VerifyPassword(hash, strings.TrimSpace(code)) {
			_, _ = s.db.ExecContext(ctx,
				`UPDATE admin_recovery_codes SET used_at = ? WHERE id = ?`,
				time.Now().UTC(), id)
			return true
		}
	}
	return false
}

// IPLocked reports whether this address has failed too often recently.
//
// Checked before the password is looked at, so a locked address cannot
// use response timing to learn which accounts exist.
func (s *Service) IPLocked(ctx context.Context, ip string) bool {
	var until sql.NullTime
	err := s.db.QueryRowContext(ctx,
		`SELECT locked_until FROM login_attempts WHERE ip = ?`, ip).Scan(&until)
	if err != nil || !until.Valid {
		return false
	}
	return time.Now().UTC().Before(until.Time)
}

// NoteLoginFailure counts a failure for this address and locks it at ten.
//
// Ten rather than the five an account gets: an address legitimately
// serves several admins on a shared network, and locking a ward's whole
// NAT gateway because two people mistyped is the cure being worse.
func (s *Service) NoteLoginFailure(ctx context.Context, ip string) {
	const window = 15 * time.Minute
	_, _ = s.db.ExecContext(ctx, `
		INSERT INTO login_attempts (ip, failures, first_at)
		VALUES (?, 1, ?)
		ON DUPLICATE KEY UPDATE
		  failures = IF(first_at < ? - INTERVAL 15 MINUTE, 1, failures + 1),
		  first_at = IF(first_at < ? - INTERVAL 15 MINUTE, ?, first_at),
		  locked_until = IF(failures + 1 >= 10, ? + INTERVAL 15 MINUTE, locked_until)`,
		ip, time.Now().UTC(), time.Now().UTC(), time.Now().UTC(),
		time.Now().UTC(), time.Now().UTC())
	_ = window
}

// NoteLoginSuccess clears the counter for this address.
func (s *Service) NoteLoginSuccess(ctx context.Context, ip string) {
	_, _ = s.db.ExecContext(ctx, `DELETE FROM login_attempts WHERE ip = ?`, ip)
}

func (s *Service) Login(ctx context.Context, email, password, userAgent, ip string) (*Admin, string, error) {
	email = strings.ToLower(strings.TrimSpace(email))
	var (
		a           Admin
		idB, tenB   []byte
		hash        string
		failed      int
		lockedUntil sql.NullTime
		disabledAt  sql.NullTime
	)
	err := s.db.QueryRowContext(ctx, `
		SELECT id, tenant_id, email, display_name, password_hash, role, must_change,
		       failed_logins, locked_until, disabled_at
		  FROM admins WHERE email = ?`, email).Scan(
		&idB, &tenB, &a.Email, &a.DisplayName, &hash, &a.Role, &a.MustChange,
		&failed, &lockedUntil, &disabledAt)
	if errors.Is(err, sql.ErrNoRows) {
		// Burn the same time as a real check, so a missing email is not
		// distinguishable from a wrong password by timing.
		VerifyPassword("$argon2id$v=19$m=65536,t=3,p=4$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", password)
		return nil, "", ErrBadCredentials
	}
	if err != nil {
		return nil, "", fmt.Errorf("adminauth.Login: %w", err)
	}
	_ = a.ID.Scan(idB)
	_ = a.TenantID.Scan(tenB)
	if disabledAt.Valid {
		return nil, "", ErrDisabled
	}
	if lockedUntil.Valid && lockedUntil.Time.After(time.Now()) {
		return nil, "", ErrLocked
	}
	if !VerifyPassword(hash, password) {
		failed++
		if failed >= MaxFailedLogins {
			_, _ = s.db.ExecContext(ctx, `UPDATE admins SET failed_logins = 0, locked_until = ? WHERE id = ?`,
				time.Now().Add(LockoutDuration), a.ID.Bytes())
			return nil, "", ErrLocked
		}
		_, _ = s.db.ExecContext(ctx, `UPDATE admins SET failed_logins = ? WHERE id = ?`, failed, a.ID.Bytes())
		return nil, "", ErrBadCredentials
	}
	_, _ = s.db.ExecContext(ctx, `UPDATE admins SET failed_logins = 0, locked_until = NULL WHERE id = ?`, a.ID.Bytes())

	token, err := s.openSession(ctx, a.ID, userAgent, ip)
	if err != nil {
		return nil, "", err
	}
	return &a, token, nil
}

func (s *Service) openSession(ctx context.Context, adminID domain.ID, userAgent, ip string) (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	token := base64.RawURLEncoding.EncodeToString(raw)
	h := sha256.Sum256([]byte(token))
	if _, err := s.db.ExecContext(ctx, `
		INSERT INTO admin_sessions (id, admin_id, token_hash, expires_at, user_agent, ip)
		VALUES (?, ?, ?, ?, ?, ?)`,
		domain.NewID().Bytes(), adminID.Bytes(), h[:], time.Now().Add(AbsoluteTimeout),
		truncate(userAgent, 255), truncate(ip, 45)); err != nil {
		return "", fmt.Errorf("adminauth.openSession: %w", err)
	}
	return token, nil
}

// Resolve turns a cookie value into the admin it belongs to, sliding
// the idle window. ErrNoSession for anything that does not resolve.
func (s *Service) Resolve(ctx context.Context, token string) (*Admin, error) {
	if token == "" {
		return nil, ErrNoSession
	}
	h := sha256.Sum256([]byte(token))
	var (
		a          Admin
		idB, tenB  []byte
		sessID     []byte
		lastUsed   time.Time
		expires    time.Time
		disabledAt sql.NullTime
	)
	err := s.db.QueryRowContext(ctx, `
		SELECT s.id, s.last_used_at, s.expires_at,
		       a.id, a.tenant_id, a.email, a.display_name, a.role, a.must_change, a.disabled_at
		  FROM admin_sessions s JOIN admins a ON a.id = s.admin_id
		 WHERE s.token_hash = ?`, h[:]).Scan(
		&sessID, &lastUsed, &expires,
		&idB, &tenB, &a.Email, &a.DisplayName, &a.Role, &a.MustChange, &disabledAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNoSession
	}
	if err != nil {
		return nil, fmt.Errorf("adminauth.Resolve: %w", err)
	}
	now := time.Now()
	if disabledAt.Valid || now.After(expires) || now.Sub(lastUsed) > IdleTimeout {
		_, _ = s.db.ExecContext(ctx, `DELETE FROM admin_sessions WHERE id = ?`, sessID)
		return nil, ErrNoSession
	}
	// Slide. Write at most once a minute so a busy console does not turn
	// every request into an UPDATE.
	if now.Sub(lastUsed) > time.Minute {
		_, _ = s.db.ExecContext(ctx, `UPDATE admin_sessions SET last_used_at = ? WHERE id = ?`, now, sessID)
	}
	_ = a.ID.Scan(idB)
	_ = a.TenantID.Scan(tenB)
	return &a, nil
}

func (s *Service) Logout(ctx context.Context, token string) error {
	h := sha256.Sum256([]byte(token))
	_, err := s.db.ExecContext(ctx, `DELETE FROM admin_sessions WHERE token_hash = ?`, h[:])
	return err
}

// ChangePassword verifies the current one, sets the new one, clears
// must_change, and ends every other session — a changed password should
// log out whoever else has it.
func (s *Service) ChangePassword(ctx context.Context, adminID domain.ID, current, next, keepToken string) error {
	var hash string
	if err := s.db.QueryRowContext(ctx, `SELECT password_hash FROM admins WHERE id = ?`, adminID.Bytes()).Scan(&hash); err != nil {
		return err
	}
	if !VerifyPassword(hash, current) {
		return ErrBadCredentials
	}
	newHash, err := HashPassword(next)
	if err != nil {
		return err
	}
	if _, err := s.db.ExecContext(ctx, `UPDATE admins SET password_hash = ?, must_change = FALSE WHERE id = ?`,
		newHash, adminID.Bytes()); err != nil {
		return err
	}
	keep := sha256.Sum256([]byte(keepToken))
	_, err = s.db.ExecContext(ctx, `DELETE FROM admin_sessions WHERE admin_id = ? AND token_hash <> ?`,
		adminID.Bytes(), keep[:])
	return err
}

func (s *Service) Sessions(ctx context.Context, adminID domain.ID) ([]Session, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, created_at, last_used_at, expires_at, user_agent, ip
		  FROM admin_sessions WHERE admin_id = ? ORDER BY last_used_at DESC`, adminID.Bytes())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Session
	for rows.Next() {
		var sess Session
		var idB []byte
		if err := rows.Scan(&idB, &sess.CreatedAt, &sess.LastUsedAt, &sess.ExpiresAt, &sess.UserAgent, &sess.IP); err != nil {
			return nil, err
		}
		_ = sess.ID.Scan(idB)
		sess.AdminID = adminID
		out = append(out, sess)
	}
	return out, rows.Err()
}

func (s *Service) RevokeSession(ctx context.Context, adminID, sessionID domain.ID) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM admin_sessions WHERE id = ? AND admin_id = ?`,
		sessionID.Bytes(), adminID.Bytes())
	return err
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
