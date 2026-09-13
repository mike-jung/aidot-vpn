package devices

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/aidotvpn/server/internal/domain"
)

// SettingEnrollmentPassword is the shared secret a device presents when
// requesting enrolment.
const SettingEnrollmentPassword = "enrollment_password"

// DefaultEnrollmentPassword seeds a new install.
//
// Short and typeable, because it is typed on a phone keypad by whoever
// is holding the handset. `changeme_enroll_password` was none of those
// things — 24 characters, mixed case, underscores — and a password
// people cannot type is one they write on a sticky note.
//
// Obviously a placeholder, so nobody mistakes it for a considered
// choice. The console shows it with a warning until it is changed.
const DefaultEnrollmentPassword = "aidot1234"

// GetSetting returns a tenant setting, or fallback when unset.
func (s *Service) GetSetting(ctx context.Context, tenantID domain.ID, name, fallback string) string {
	if tenantID.IsZero() {
		tenantID = s.tenantID
	}
	var stored string
	err := s.db.QueryRowContext(ctx,
		`SELECT value FROM settings WHERE tenant_id = ? AND name = ?`,
		tenantID.Bytes(), name).Scan(&stored)
	if errors.Is(err, sql.ErrNoRows) || err != nil || stored == "" {
		return fallback
	}

	v, err := openSetting(stored)
	if err != nil {
		// A stored value we cannot decrypt is a misconfigured key, and
		// returning the fallback silently would let an operator change
		// the password, restart with the wrong key, and find the old one
		// apparently back. Callers that need to distinguish use
		// GetSettingErr.
		return fallback
	}
	return v
}

// GetSettingErr is GetSetting with the decryption failure surfaced.
//
// The console needs this: "the key is wrong" and "nobody has set this"
// look identical through GetSetting, and only one of them is something
// an operator can fix.
func (s *Service) GetSettingErr(ctx context.Context, tenantID domain.ID, name string) (string, error) {
	if tenantID.IsZero() {
		tenantID = s.tenantID
	}
	var stored string
	err := s.db.QueryRowContext(ctx,
		`SELECT value FROM settings WHERE tenant_id = ? AND name = ?`,
		tenantID.Bytes(), name).Scan(&stored)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("GetSettingErr: %w", err)
	}
	return openSetting(stored)
}

// SetSetting writes a tenant setting.
func (s *Service) SetSetting(ctx context.Context, tenantID, actor domain.ID, name, value string) error {
	if tenantID.IsZero() {
		tenantID = s.tenantID
	}
	var by any
	if !actor.IsZero() {
		by = actor.Bytes()
	}
	sealed, err := sealSetting(value)
	if err != nil {
		return fmt.Errorf("SetSetting: %w", err)
	}

	_, err = s.db.ExecContext(ctx, `
		INSERT INTO settings (tenant_id, name, value, updated_by)
		VALUES (?, ?, ?, ?)
		ON DUPLICATE KEY UPDATE value = VALUES(value), updated_by = VALUES(updated_by)`,
		tenantID.Bytes(), name, sealed, by)
	if err != nil {
		return fmt.Errorf("SetSetting: %w", err)
	}
	return nil
}

// ValidateEnrollmentPassword rejects values that would be worse than the
// default they replace.
//
// Six characters, no spaces. Not a policy anyone would call strong — and
// strength is not what this password provides. It keeps a stranger on
// the wifi from filling the approval queue; the approval itself is the
// control. A long-password rule here would push operators toward writing
// it down, which costs more than it buys.
func ValidateEnrollmentPassword(v string) error {
	if len([]rune(v)) < 6 {
		return errors.New("6자 이상이어야 합니다")
	}
	if strings.ContainsAny(v, " \t\n") {
		return errors.New("공백은 쓸 수 없습니다")
	}
	return nil
}
