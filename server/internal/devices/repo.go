// Repository: persistence layer for devices, device_keys, device_psks.
//
// Conventions:
//
//   - All methods take a context and an explicit *sql.DB or *sql.Tx via
//     the `executor` interface. Callers control transaction boundaries.
//   - Soft-deleted rows are filtered out of read queries (`deleted_at IS NULL`).
//   - All methods return ErrNotFound (wrapping sql.ErrNoRows) when a
//     single-row lookup misses, so callers use errors.Is to handle.
package devices

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/aidotvpn/server/internal/domain"
)

// ErrNotFound mirrors db.ErrNotFound so callers in this package don't
// need to import the db package just to handle missing rows.
var ErrNotFound = errors.New("devices: not found")

// executor is the subset of *sql.DB / *sql.Tx the repository needs.
// Callers pass either to control transaction boundaries.
type executor interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// Tenant is the subset of tenants we need at the device layer.
type Tenant struct {
	ID       domain.ID
	IPv4Pool string // CIDR
	IPv6Pool string // CIDR or ""
}

// Repo is a stateless wrapper around the database used by Service.
type Repo struct{}

// NewRepo returns a fresh repository. Stateless because all state lives
// in the executor passed per-call.
func NewRepo() *Repo { return &Repo{} }

// findDeviceByInstall looks up a device by (user_id, install_id),
// including soft-deleted rows.
//
// Revoking sets deleted_at, and this query used to filter those out — so
// a phone that had been revoked and then enrolled again was not found,
// registration tried to INSERT, and the unique index on
// (user_id, install_id) rejected it. The soft-deleted row still counts.
//
// The caller reactivates what it finds, which is the same handling a
// live re-registration already got. Returning the row is what lets a
// revoked handset come back — the ordinary case after an admin revokes
// something and the operator enrols it again.
func (r *Repo) findDeviceByInstall(ctx context.Context, q executor, userID domain.ID, installID string) (*Device, error) {
	row := q.QueryRowContext(ctx, `
		SELECT id, tenant_id, user_id, install_id, display_name, platform,
		       os_version, app_version, status, last_seen_at, created_at,
		       app_filter_mode, app_filter_packages,
		       deployment_mode, COALESCE(host_package, '')
		FROM devices
		WHERE user_id = ? AND install_id = ?
		LIMIT 1`,
		userID.Bytes(), installID)
	return scanDevice(row)
}

// findDeviceByID returns a device by primary key.
func (r *Repo) findDeviceByID(ctx context.Context, q executor, id domain.ID) (*Device, error) {
	row := q.QueryRowContext(ctx, `
		SELECT id, tenant_id, user_id, install_id, display_name, platform,
		       os_version, app_version, status, last_seen_at, created_at,
		       app_filter_mode, app_filter_packages,
		       deployment_mode, COALESCE(host_package, '')
		FROM devices
		WHERE id = ? AND deleted_at IS NULL
		LIMIT 1`,
		id.Bytes())
	return scanDevice(row)
}

// listDevicesByTenant returns every non-deleted device in a tenant.
//
// For admins. `listDevicesByUser` shows the caller their own handsets,
// which is right for a clinician and wrong for the person who has to
// assign policies: an admin logging in saw an empty list even though
// devices were registered, because none of them were theirs.
//
// Tenant-scoped, not global — an admin of one hospital has no business
// seeing another's.
func (r *Repo) listDevicesByTenant(ctx context.Context, q executor, tenantID domain.ID) ([]Device, error) {
	rows, err := q.QueryContext(ctx, `
		SELECT id, tenant_id, user_id, install_id, display_name, platform,
		       os_version, app_version, status, last_seen_at, created_at,
		       app_filter_mode, app_filter_packages,
		       deployment_mode, COALESCE(host_package, '')
		FROM devices
		WHERE tenant_id = ? AND deleted_at IS NULL
		ORDER BY created_at DESC`,
		tenantID.Bytes())
	if err != nil {
		return nil, fmt.Errorf("listDevicesByTenant: %w", err)
	}
	defer rows.Close()

	var out []Device
	for rows.Next() {
		d, err := scanDeviceRow(rows)
		if err != nil {
			return nil, fmt.Errorf("listDevicesByTenant: %w", err)
		}
		out = append(out, *d)
	}
	return out, rows.Err()
}

// listDevicesByUser returns all non-deleted devices for a user, newest first.
func (r *Repo) listDevicesByUser(ctx context.Context, q executor, userID domain.ID) ([]Device, error) {
	rows, err := q.QueryContext(ctx, `
		SELECT id, tenant_id, user_id, install_id, display_name, platform,
		       os_version, app_version, status, last_seen_at, created_at,
		       app_filter_mode, app_filter_packages,
		       deployment_mode, COALESCE(host_package, '')
		FROM devices
		WHERE user_id = ? AND deleted_at IS NULL
		ORDER BY created_at DESC`,
		userID.Bytes())
	if err != nil {
		return nil, fmt.Errorf("listDevicesByUser: %w", err)
	}
	defer rows.Close()

	var out []Device
	for rows.Next() {
		d, err := scanDeviceRow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *d)
	}
	return out, rows.Err()
}

// reactivateDevice clears a soft delete, restores active status, and
// drops the old policy.
//
// Dropping the policy is the part that matters. 1.4.3 added this so a
// revoked handset could enrol again, and left policy_id alone — so a
// device revoked and re-approved came back bound to whatever it had
// before, even when the admin deliberately chose nothing:
//
//	폐기 전   정책: 검증용
//	재승인    정책을 고르지 않음
//	재등록 후 정책: 검증용      ← nobody asked for this
//
// Revoking is how an admin removes a device's access. Handing that
// access back on re-registration undoes the revocation while looking
// like an ordinary enrolment. If the device should have the same policy
// again, the approval dialog is where that gets said.
func (r *Repo) reactivateDevice(ctx context.Context, q executor, id domain.ID) error {
	_, err := q.ExecContext(ctx, `
		UPDATE devices
		SET deleted_at = NULL, status = 'active', policy_id = NULL
		WHERE id = ?`, id.Bytes())
	if err != nil {
		return fmt.Errorf("reactivateDevice: %w", err)
	}
	return nil
}

// insertDevice inserts a new device row.
func (r *Repo) insertDevice(ctx context.Context, q executor, d *Device) error {
	if d.ID.IsZero() {
		d.ID = domain.NewID()
	}
	if d.CreatedAt.IsZero() {
		d.CreatedAt = time.Now().UTC()
	}
	if d.Status == "" {
		d.Status = StatusPendingAttest
	}
	if !d.DeploymentMode.Valid() {
		d.DeploymentMode = DeploymentStandalone
	}
	_, err := q.ExecContext(ctx, `
		INSERT INTO devices
		  (id, tenant_id, user_id, install_id, display_name, platform,
		   os_version, app_version, model, os_sdk, status, created_at,
		   deployment_mode, host_package)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		d.ID.Bytes(), d.TenantID.Bytes(), d.UserID.Bytes(),
		d.InstallID, d.DisplayName, string(d.Platform),
		// model and os_sdk were missing here: 1.9.0 added model to the
		// re-register UPDATE and to the schema but not to the INSERT, so
		// a first enrolment stored nothing and only a later re-register
		// filled it in. Found while wiring the posture check, which
		// depends on os_sdk arriving at enrolment.
		d.OSVersion, d.AppVersion, nullIfEmpty(d.Model), nullIfZero(d.OSSdk),
		string(d.Status), d.CreatedAt,
		string(d.DeploymentMode), nullIfEmpty(d.HostPackage))
	if err != nil {
		return fmt.Errorf("insertDevice: %w", err)
	}
	return nil
}

// updateDeviceStatus sets the status and bumps last_seen_at.
func (r *Repo) updateDeviceStatus(ctx context.Context, q executor, id domain.ID, status Status) error {
	res, err := q.ExecContext(ctx, `
		UPDATE devices
		SET status = ?, last_seen_at = NOW(6)
		WHERE id = ? AND deleted_at IS NULL`,
		string(status), id.Bytes())
	if err != nil {
		return fmt.Errorf("updateDeviceStatus: %w", err)
	}
	rows, _ := res.RowsAffected()
	if rows == 0 {
		return ErrNotFound
	}
	return nil
}

// updateAppFilter writes (mode, packages) to a device. The packages
// argument is marshalled to JSON in-Go before being sent — the SQL
// column is JSON-typed so we hand it a JSON document. Pass an empty
// slice (not nil) for an empty list; both work but '[]' is the
// convention.
func (r *Repo) updateAppFilter(ctx context.Context, q executor, id domain.ID, mode AppFilterMode, packages []string) error {
	if packages == nil {
		packages = []string{}
	}
	payload, err := json.Marshal(packages)
	if err != nil {
		// json.Marshal on []string never errors in practice, but we
		// surface it explicitly rather than relying on `_ = err`.
		return fmt.Errorf("updateAppFilter: marshal: %w", err)
	}
	res, err := q.ExecContext(ctx, `
		UPDATE devices
		SET app_filter_mode = ?, app_filter_packages = ?
		WHERE id = ? AND deleted_at IS NULL`,
		string(mode), payload, id.Bytes())
	if err != nil {
		return fmt.Errorf("updateAppFilter: %w", err)
	}
	rows, _ := res.RowsAffected()
	if rows == 0 {
		return ErrNotFound
	}
	return nil
}

// softDeleteDevice marks a device as revoked and stamps deleted_at.
// Active keys for the device are revoked as part of the same logical step
// (the caller is responsible for calling revokeAllKeys in the same Tx).
func (r *Repo) softDeleteDevice(ctx context.Context, q executor, id domain.ID) error {
	_, err := q.ExecContext(ctx, `
		UPDATE devices
		SET status = 'revoked', deleted_at = NOW(6)
		WHERE id = ? AND deleted_at IS NULL`,
		id.Bytes())
	return err
}

// insertDeviceKey inserts a device_keys row.
func (r *Repo) insertDeviceKey(ctx context.Context, q executor, k *DeviceKey) error {
	if k.ID.IsZero() {
		k.ID = domain.NewID()
	}
	if k.ActivatedAt.IsZero() {
		k.ActivatedAt = time.Now().UTC()
	}
	var v4, v6 any
	if k.IPv4.IsValid() {
		v4 = domain.IPToBytes(k.IPv4)
	}
	if k.IPv6.IsValid() {
		v6 = domain.IPToBytes(k.IPv6)
	}
	var expiresAt any
	if k.ExpiresAt != nil {
		expiresAt = *k.ExpiresAt
	}
	_, err := q.ExecContext(ctx, `
		INSERT INTO device_keys
		  (id, device_id, public_key, ipv4_addr, ipv6_addr, activated_at, expires_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		k.ID.Bytes(), k.DeviceID.Bytes(), k.PublicKey, v4, v6,
		k.ActivatedAt, expiresAt)
	if err != nil {
		return fmt.Errorf("insertDeviceKey: %w", err)
	}
	return nil
}

// revokeAllKeys marks every active device_key for `deviceID` as revoked.
func (r *Repo) revokeAllKeys(ctx context.Context, q executor, deviceID domain.ID) error {
	_, err := q.ExecContext(ctx, `
		UPDATE device_keys
		SET revoked_at = NOW(6)
		WHERE device_id = ? AND revoked_at IS NULL`,
		deviceID.Bytes())
	return err
}

// findActiveKey returns the currently-active key for a device. There must
// be at most one such key after a successful registration / rotation.
func (r *Repo) findActiveKey(ctx context.Context, q executor, deviceID domain.ID) (*DeviceKey, error) {
	row := q.QueryRowContext(ctx, `
		SELECT id, device_id, public_key, ipv4_addr, ipv6_addr,
		       activated_at, expires_at, revoked_at
		FROM device_keys
		WHERE device_id = ? AND revoked_at IS NULL
		ORDER BY activated_at DESC
		LIMIT 1`,
		deviceID.Bytes())
	return scanDeviceKey(row)
}

// insertPSK inserts a device_psks row.
func (r *Repo) insertPSK(ctx context.Context, q executor, p *PSK) error {
	if p.ID.IsZero() {
		p.ID = domain.NewID()
	}
	if p.ActivatedAt.IsZero() {
		p.ActivatedAt = time.Now().UTC()
	}
	if p.Source == "" {
		p.Source = PSKClassical
	}
	var expiresAt any
	if p.ExpiresAt != nil {
		expiresAt = *p.ExpiresAt
	}
	_, err := q.ExecContext(ctx, `
		INSERT INTO device_psks
		  (id, device_key_id, psk, source, activated_at, expires_at)
		VALUES (?, ?, ?, ?, ?, ?)`,
		p.ID.Bytes(), p.DeviceKeyID.Bytes(), p.PSK, string(p.Source),
		p.ActivatedAt, expiresAt)
	if err != nil {
		return fmt.Errorf("insertPSK: %w", err)
	}
	return nil
}

// findTenant returns the tenant row for IP-pool resolution.
func (r *Repo) findTenant(ctx context.Context, q executor, id domain.ID) (*Tenant, error) {
	row := q.QueryRowContext(ctx, `
		SELECT id, ipv4_pool_addr, ipv4_pool_bits, ipv6_pool_addr, ipv6_pool_bits
		FROM tenants
		WHERE id = ? AND deleted_at IS NULL
		LIMIT 1`,
		id.Bytes())
	var (
		idBytes []byte
		v4addr  []byte
		v4bits  int
		v6addr  []byte
		v6bits  sql.NullInt64
	)
	if err := row.Scan(&idBytes, &v4addr, &v4bits, &v6addr, &v6bits); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("findTenant: %w", err)
	}
	t := &Tenant{}
	if err := t.ID.Scan(idBytes); err != nil {
		return nil, err
	}
	if len(v4addr) == 4 {
		t.IPv4Pool = fmt.Sprintf("%d.%d.%d.%d/%d", v4addr[0], v4addr[1], v4addr[2], v4addr[3], v4bits)
	}
	if len(v6addr) == 16 && v6bits.Valid {
		addr, _ := domain.IPFromBytes(v6addr)
		t.IPv6Pool = fmt.Sprintf("%s/%d", addr.String(), v6bits.Int64)
	}
	return t, nil
}

// --- scanners ----------------------------------------------------------

type rowScanner interface {
	Scan(dest ...any) error
}

func scanDevice(s rowScanner) (*Device, error) {
	d := &Device{}
	var (
		idBytes, tenantBytes, userBytes []byte
		platform                        string
		status                          string
		lastSeen                        sql.NullTime
		osVersion, appVersion           sql.NullString
		appFilterMode                   string
		appFilterPackagesJSON           []byte
		deploymentMode                  string
		hostPackage                     string
	)
	err := s.Scan(&idBytes, &tenantBytes, &userBytes,
		&d.InstallID, &d.DisplayName, &platform,
		&osVersion, &appVersion, &status, &lastSeen, &d.CreatedAt,
		&appFilterMode, &appFilterPackagesJSON,
		&deploymentMode, &hostPackage)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("scanDevice: %w", err)
	}
	if err := d.ID.Scan(idBytes); err != nil {
		return nil, err
	}
	if err := d.TenantID.Scan(tenantBytes); err != nil {
		return nil, err
	}
	if err := d.UserID.Scan(userBytes); err != nil {
		return nil, err
	}
	d.Platform = Platform(platform)
	// Older and minimal clients may omit these nullable metadata fields.
	d.OSVersion, d.AppVersion = osVersion.String, appVersion.String
	d.Status = Status(status)
	d.DeploymentMode = DeploymentMode(deploymentMode)
	if !d.DeploymentMode.Valid() {
		// Rows written before migration 0010 carry the column default,
		// but a hand-edited value shouldn't propagate as an unknown mode.
		d.DeploymentMode = DeploymentStandalone
	}
	d.HostPackage = hostPackage
	if lastSeen.Valid {
		t := lastSeen.Time
		d.LastSeenAt = &t
	}

	// Parse app filter. The JSON column is non-NULL with default '[]',
	// so an empty `app_filter_packages` is `[]` not NULL. The mode
	// column is non-NULL with default 'off'. We tolerate empty/garbage
	// JSON by falling back to an empty package list — admins can fix
	// this from the console without needing a DB intervention.
	d.AppFilter.Mode = AppFilterMode(appFilterMode)
	if d.AppFilter.Mode == "" {
		d.AppFilter.Mode = AppFilterOff
	}
	if len(appFilterPackagesJSON) > 0 {
		if err := json.Unmarshal(appFilterPackagesJSON, &d.AppFilter.Packages); err != nil {
			// Don't fail the whole device load on malformed JSON; log
			// and treat as empty. This keeps the console responsive
			// during a partial migration window.
			d.AppFilter.Packages = nil
		}
	}
	return d, nil
}

// scanDeviceRow is a rows-friendly version of scanDevice.
func scanDeviceRow(s rowScanner) (*Device, error) {
	return scanDevice(s)
}

func scanDeviceKey(s rowScanner) (*DeviceKey, error) {
	k := &DeviceKey{}
	var (
		idBytes, devBytes []byte
		v4, v6            []byte
		expires, revoked  sql.NullTime
	)
	err := s.Scan(&idBytes, &devBytes, &k.PublicKey, &v4, &v6,
		&k.ActivatedAt, &expires, &revoked)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("scanDeviceKey: %w", err)
	}
	if err := k.ID.Scan(idBytes); err != nil {
		return nil, err
	}
	if err := k.DeviceID.Scan(devBytes); err != nil {
		return nil, err
	}
	if len(v4) == 4 {
		k.IPv4, _ = domain.IPFromBytes(v4)
	}
	if len(v6) == 16 {
		k.IPv6, _ = domain.IPFromBytes(v6)
	}
	if expires.Valid {
		t := expires.Time
		k.ExpiresAt = &t
	}
	if revoked.Valid {
		t := revoked.Time
		k.RevokedAt = &t
	}
	return k, nil
}

// nullIfEmpty stores NULL rather than an empty string, so "not reported"
// and "reported as blank" stay distinguishable in the column.
func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}
