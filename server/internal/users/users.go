// Package users provides lookup and upsert for the `users` table keyed by
// Keycloak's `sub` claim.
//
// On first login from a Keycloak user we create a row mapping the OIDC
// subject to a UUIDv7 we generate ourselves. That UUIDv7 then becomes
// the canonical user_id used everywhere else in the system (devices,
// audit_log, allowlist enrollments, ...).
//
// We do NOT trust Keycloak's `sub` to be a UUID we can store directly,
// because it isn't always — different IdPs return different `sub`
// formats. Storing it as a VARCHAR and indirecting through our own
// UUIDv7 keeps the schema portable.
package users

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/aidotvpn/server/internal/domain"
)

// User is one row of the users table.
type User struct {
	ID          domain.ID
	TenantID    domain.ID
	KCSubject   string
	Email       string
	DisplayName string
	Status      string
}

// Repo is the lookup/upsert handle.
type Repo struct {
	db *sql.DB
}

// New returns a Repo bound to the given database.
func New(db *sql.DB) *Repo {
	return &Repo{db: db}
}

// FindOrCreate returns an existing user by Keycloak subject, creating one
// in the given tenant if no row matches.
//
// It is safe to call concurrently for the same subject; the second caller
// will simply observe the first one's row via the unique key on kc_subject.
func (r *Repo) FindOrCreate(ctx context.Context, tenantID domain.ID, kcSubject, email, displayName string) (*User, error) {
	if kcSubject == "" {
		return nil, errors.New("users.FindOrCreate: kc_subject required")
	}
	if u, err := r.findBySubject(ctx, kcSubject); err == nil {
		return u, nil
	} else if !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}

	u := &User{
		ID:          domain.NewID(),
		TenantID:    tenantID,
		KCSubject:   kcSubject,
		Email:       email,
		DisplayName: displayName,
		Status:      "active",
	}
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO users (id, tenant_id, kc_subject, email, display_name, status, last_login_at)
		VALUES (?, ?, ?, ?, ?, 'active', CURRENT_TIMESTAMP(6))
		ON DUPLICATE KEY UPDATE
		  email = VALUES(email),
		  display_name = COALESCE(VALUES(display_name), display_name),
		  -- last_login_at (wired in 0.23.0). The column has existed since
		  -- 0001 and was never written, so the console could show a fleet
		  -- of users with no way to tell an active account from one
		  -- belonging to someone who left months ago.
		  --
		  -- Updated here rather than in a dedicated call because this is
		  -- the only place a token is exchanged for a user: every
		  -- authenticated request passes through it, so "last seen with
		  -- a valid token" and "last login" are the same event as far as
		  -- the controller can observe.
		  --
		  -- Set on INSERT too. End-to-end testing caught it NULL for a
		  -- brand-new account: the ON DUPLICATE branch only runs on the
		  -- second call, so a user who registered and then never came
		  -- back read as "never logged in" — the exact population an
		  -- admin most wants to find.
		  last_login_at = CURRENT_TIMESTAMP(6)`,
		u.ID.Bytes(), tenantID.Bytes(), kcSubject, email, nullStr(displayName))
	if err != nil {
		return nil, fmt.Errorf("users.FindOrCreate insert: %w", err)
	}
	// Re-read to pick up the existing row if INSERT was a no-op due to
	// the unique key (concurrent caller won the race).
	return r.findBySubject(ctx, kcSubject)
}

func (r *Repo) findBySubject(ctx context.Context, kcSubject string) (*User, error) {
	row := r.db.QueryRowContext(ctx, `
		SELECT id, tenant_id, kc_subject, email,
		       COALESCE(display_name, ''), status
		FROM users
		WHERE kc_subject = ?
		LIMIT 1`,
		kcSubject)
	var (
		idBytes, tenantBytes []byte
		u                    User
	)
	if err := row.Scan(&idBytes, &tenantBytes, &u.KCSubject, &u.Email, &u.DisplayName, &u.Status); err != nil {
		return nil, err
	}
	if err := u.ID.Scan(idBytes); err != nil {
		return nil, err
	}
	if err := u.TenantID.Scan(tenantBytes); err != nil {
		return nil, err
	}
	return &u, nil
}

func nullStr(s string) any {
	if s == "" {
		return nil
	}
	return s
}
