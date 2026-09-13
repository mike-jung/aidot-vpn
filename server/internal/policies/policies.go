// Package policies implements the controller side of split-tunnel policy.
//
// What this package owns:
//
//   - The `policies` table (per-tenant named policies).
//   - The `policy_allowed_ips` table (the AllowedIPs CIDR list each policy
//     permits — drives WireGuard's split-tunnel routing on clients).
//   - The `devices.policy_id` column (which device is assigned to which
//     policy; NULL means the device is unprovisioned and reaches nothing).
//   - The `policy_rules` table (L4 action/protocol/port refinements).
//   - `policies.route_scope` (split tunnel vs lockdown).
//
// What this package does NOT own:
//
//   - Per-app split tunnel selection. Which APPS enter the tunnel is
//     `devices.app_filter_mode` (owned by the devices package) and is
//     enforced by Android's VpnService, not by us. This package owns the
//     orthogonal axis: which DESTINATIONS are reachable, and — via
//     RouteScope — what happens to traffic that isn't.
//
// Note the 0.10.0/0.11.0 corrections to the above: `policy_rules` is no
// longer legacy (GetEffectiveRules renders it into the gateway's nftables
// ruleset), and "no policy → safe full-tunnel default" was exactly
// backwards — an unbound device now reaches nothing.
//
// Validation philosophy:
//
//	We accept text-form CIDRs ("10.10.0.0/16", "2001:db8::/32") and
//	validate them with net/netip on write. The DB column stores the
//	canonical text form (after .Masked()) so that "10.10.0.5/16" is
//	normalised to "10.10.0.0/16" — preventing two rows that mean the
//	same network from sneaking past the UNIQUE KEY.
package policies

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/aidotvpn/server/internal/audit"
	"github.com/aidotvpn/server/internal/domain"
)

// ErrNotFound is returned when a policy or allowed-ip row is missing.
var ErrNotFound = errors.New("policies: not found")

// ErrInvalidCIDR is returned when a caller submits a malformed prefix.
var ErrInvalidCIDR = errors.New("policies: invalid CIDR")

// Policy is one row of the `policies` table, with the AllowedIPs hydrated
// when callers ask for it via WithAllowedIPs. Plain Get/List don't fill
// AllowedIPs — that would be N+1 queries — so callers explicitly opt in.
type Policy struct {
	ID          domain.ID
	TenantID    domain.ID
	Name        string
	Description string
	Enabled     bool
	Precedence  int

	// Rewrite the source address for this policy's destinations.
	//
	// Added as a column in 1.6.0 and never surfaced — so the feature
	// existed in the schema and the gateway and could not be turned on
	// from anywhere. Costs the audit trail; see the migration.
	SourceNAT bool

	// How devices under this policy reach the gateway.
	//
	//   direct  UDP — fast, and blocked on some networks
	//   auto    direct first, relay if that fails
	//   relay   always relay
	//
	// The relay carries the same WireGuard packets inside
	// WebSocket-over-TLS on 443. Same encryption and keys; only the
	// envelope differs, so a network that blocks UDP still lets it
	// through.
	EndpointMode string

	// Where devices under this policy reach the controller.
	//
	//   direct  the address compiled into the app
	//   tunnel  10.78.0.1, proxied by the gateway
	//
	// Hiding it costs a dependency: the tunnel route only works while
	// the gateway proxy is up, and a device that cannot reach the
	// controller cannot be told it was revoked.
	ControlChannel string
	CreatedAt      time.Time
	UpdatedAt      time.Time

	// AllowedIPs is populated by ListAllowedIPs and the *WithAllowedIPs
	// variants below; nil when not yet loaded.
	AllowedIPs []AllowedIP `json:"allowed_ips,omitempty"`
}

// AllowedIP is one row of the `policy_allowed_ips` table.
type AllowedIP struct {
	ID          domain.ID
	PolicyID    domain.ID
	CIDR        string // canonical, masked text form
	Description string
	CreatedAt   time.Time
}

// Service exposes the policy operations to other packages and the REST API.
type Service struct {
	db    *sql.DB
	audit *audit.Writer
}

// New builds a Service. db and audit are required.
func New(db *sql.DB, auditWriter *audit.Writer) (*Service, error) {
	if db == nil {
		return nil, errors.New("policies.New: DB is required")
	}
	if auditWriter == nil {
		return nil, errors.New("policies.New: Audit is required")
	}
	return &Service{db: db, audit: auditWriter}, nil
}

// ----- Policy CRUD ---------------------------------------------------------

// Create makes a new policy in the given tenant. Name must be unique
// per tenant (DB constraint). actor is recorded in the audit trail.
func (s *Service) Create(ctx context.Context, tenantID, actor domain.ID, name, description string) (*Policy, error) {
	if strings.TrimSpace(name) == "" {
		return nil, errors.New("policies.Create: name required")
	}
	p := &Policy{
		ID:          domain.NewID(),
		TenantID:    tenantID,
		Name:        name,
		Description: description,
		Enabled:     true,
		Precedence:  100,
		CreatedAt:   time.Now().UTC(),
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO policies (id, tenant_id, name, description, enabled, precedence)
		VALUES (?, ?, ?, ?, TRUE, 100)`,
		p.ID.Bytes(), tenantID.Bytes(), name, nullStr(description))
	if err != nil {
		return nil, fmt.Errorf("policies.Create: %w", err)
	}
	if err := s.writeAudit(ctx, tenantID, actor, "policy.create", "policy", &p.ID, map[string]any{"name": name}); err != nil {
		return nil, err
	}
	return p, nil
}

// List returns all non-deleted policies for a tenant, ordered by name.
// AllowedIPs are NOT loaded (use ListAllowedIPs separately).
func (s *Service) List(ctx context.Context, tenantID domain.ID) ([]Policy, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, tenant_id, name, COALESCE(description, ''), enabled,
		       source_nat, endpoint_mode, control_channel, precedence,
		       created_at, updated_at
		FROM policies
		WHERE tenant_id = ? AND deleted_at IS NULL
		ORDER BY name ASC`,
		tenantID.Bytes())
	if err != nil {
		return nil, fmt.Errorf("policies.List: %w", err)
	}
	defer rows.Close()
	var out []Policy
	for rows.Next() {
		p, err := scanPolicy(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *p)
	}
	return out, rows.Err()
}

// Get returns a single policy by ID. AllowedIPs are NOT loaded; callers
// who want them call GetWithAllowedIPs.
func (s *Service) Get(ctx context.Context, id domain.ID) (*Policy, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, tenant_id, name, COALESCE(description, ''), enabled,
		       source_nat, endpoint_mode, control_channel, precedence,
		       created_at, updated_at
		FROM policies
		WHERE id = ? AND deleted_at IS NULL
		LIMIT 1`,
		id.Bytes())
	return scanPolicy(row)
}

// GetWithAllowedIPs returns a policy with its AllowedIPs hydrated.
func (s *Service) GetWithAllowedIPs(ctx context.Context, id domain.ID) (*Policy, error) {
	p, err := s.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	ips, err := s.ListAllowedIPs(ctx, id)
	if err != nil {
		return nil, err
	}
	p.AllowedIPs = ips
	return p, nil
}

// Update changes the policy's name, description, and enabled flag.
// AllowedIPs are managed separately via Add/RemoveAllowedIP.
// UpdateTransport sets how devices under this policy reach the gateway,
// and whether their source address is rewritten.
//
// Separate from Update because these are the two settings that change
// how traffic moves rather than what it may reach. Folding them into
// the same call would let a rename silently flip the transport.
// ForDevice returns the policy bound to a device, or nil when none is.
//
// nil rather than an error for the unbound case: a device with no policy
// is an ordinary state — it is what a freshly registered one looks
// like — and callers should not have to distinguish that from a query
// failure.
func (s *Service) ForDevice(ctx context.Context, deviceID domain.ID) (*Policy, error) {
	// The device's own policy wins; otherwise it inherits its group's.
	//
	// An override rather than a merge: two policies that both mention a
	// range would need a rule for what the combination means, and there
	// is no answer to that a hospital administrator should have to
	// reason about. COALESCE picks one, and the console shows which.
	row := s.db.QueryRowContext(ctx, `
		SELECT p.id, p.tenant_id, p.name, COALESCE(p.description, ''), p.enabled,
		       p.source_nat, p.endpoint_mode, p.control_channel, p.precedence,
		       p.created_at, p.updated_at
		  FROM devices d
		  LEFT JOIN device_groups g
		         ON g.id = d.group_id AND g.tenant_id = d.tenant_id AND g.deleted_at IS NULL
		  JOIN policies p
		    ON p.id = COALESCE(d.policy_id, g.policy_id) AND p.tenant_id = d.tenant_id AND p.deleted_at IS NULL
		 WHERE d.id = ?`, deviceID.Bytes())
	p, err := scanPolicy(row)
	if errors.Is(err, ErrNotFound) {
		return nil, nil
	}
	return p, err
}

func (s *Service) UpdateTransport(
	ctx context.Context, id, actor domain.ID,
	endpointMode string, sourceNAT bool, controlChannel string,
) error {
	switch endpointMode {
	case "direct", "auto", "relay":
	default:
		return fmt.Errorf("policies.UpdateTransport: unknown endpoint mode %q", endpointMode)
	}
	switch controlChannel {
	case "direct", "tunnel":
	default:
		return fmt.Errorf("policies.UpdateTransport: unknown control channel %q", controlChannel)
	}

	p, err := s.Get(ctx, id)
	if err != nil {
		return err
	}
	if _, err := s.db.ExecContext(ctx, `
		UPDATE policies SET endpoint_mode = ?, source_nat = ?, control_channel = ?
		 WHERE id = ? AND deleted_at IS NULL`,
		endpointMode, sourceNAT, controlChannel, id.Bytes()); err != nil {
		return fmt.Errorf("policies.UpdateTransport: %w", err)
	}
	return s.writeAudit(ctx, p.TenantID, actor, "policy.transport", "policy", &id,
		map[string]any{
			"endpoint_mode":   endpointMode,
			"source_nat":      sourceNAT,
			"control_channel": controlChannel,
		})
}

func (s *Service) Update(ctx context.Context, id, actor domain.ID, name, description string, enabled bool) error {
	// Existence is checked by reading, not by counting affected rows.
	//
	// MySQL reports rows *changed*, not rows matched. Saving a form
	// without editing it — which is what 저장 does most of the time —
	// updates a row to the values it already holds, so RowsAffected is
	// 0 and the old code returned ErrNotFound for a policy that plainly
	// exists. The console showed 500 on the most ordinary action there
	// is.
	p, err := s.Get(ctx, id)
	if err != nil {
		return err
	}

	if _, err := s.db.ExecContext(ctx, `
		UPDATE policies
		   SET name = ?, description = ?, enabled = ?
		 WHERE id = ? AND deleted_at IS NULL`,
		name, nullStr(description), enabled, id.Bytes()); err != nil {
		return fmt.Errorf("policies.Update: %w", err)
	}
	return s.writeAudit(ctx, p.TenantID, actor, "policy.update", "policy", &id, map[string]any{
		"name": name, "enabled": enabled,
	})
}

// Delete soft-deletes a policy by setting deleted_at. We also unassign
// it from any devices to prevent dangling FKs from breaking the join in
// GetEffectiveAllowedIPs.
func (s *Service) Delete(ctx context.Context, id, actor domain.ID) error {
	p, err := s.Get(ctx, id)
	if err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if _, err := tx.ExecContext(ctx, `
		UPDATE devices SET policy_id = NULL WHERE policy_id = ?`, id.Bytes()); err != nil {
		return fmt.Errorf("policies.Delete unassign: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE policies SET deleted_at = CURRENT_TIMESTAMP(6) WHERE id = ?`, id.Bytes()); err != nil {
		return fmt.Errorf("policies.Delete: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	return s.writeAudit(ctx, p.TenantID, actor, "policy.delete", "policy", &id, nil)
}

// ----- AllowedIPs ----------------------------------------------------------

// AddAllowedIP appends a new CIDR to a policy. The CIDR is canonicalised
// (masked) before storage so semantically-equal CIDRs collide on the
// uq_policy_cidr unique key.
func (s *Service) AddAllowedIP(ctx context.Context, policyID, actor domain.ID, cidr, description string) (*AllowedIP, error) {
	canonical, err := normalizeCIDR(cidr)
	if err != nil {
		return nil, err
	}
	p, err := s.Get(ctx, policyID)
	if err != nil {
		return nil, err
	}
	row := &AllowedIP{
		ID:          domain.NewID(),
		PolicyID:    policyID,
		CIDR:        canonical,
		Description: description,
		CreatedAt:   time.Now().UTC(),
	}
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO policy_allowed_ips (id, policy_id, cidr, description)
		VALUES (?, ?, ?, ?)`,
		row.ID.Bytes(), policyID.Bytes(), canonical, nullStr(description))
	if err != nil {
		return nil, fmt.Errorf("policies.AddAllowedIP: %w", err)
	}
	if err := s.writeAudit(ctx, p.TenantID, actor, "policy.allowed_ip.add", "policy", &policyID, map[string]any{"cidr": canonical}); err != nil {
		return nil, err
	}
	return row, nil
}

// RemoveAllowedIP deletes a single AllowedIP row by its ID.
func (s *Service) RemoveAllowedIP(ctx context.Context, allowedIPID, actor domain.ID) error {
	// Look up policyID for the audit row before deleting.
	row := s.db.QueryRowContext(ctx, `SELECT policy_id, cidr FROM policy_allowed_ips WHERE id = ?`, allowedIPID.Bytes())
	var policyBytes []byte
	var cidr string
	if err := row.Scan(&policyBytes, &cidr); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		return err
	}
	var policyID domain.ID
	if err := policyID.Scan(policyBytes); err != nil {
		return err
	}
	p, err := s.Get(ctx, policyID)
	if err != nil {
		return err
	}
	if _, err := s.db.ExecContext(ctx, `DELETE FROM policy_allowed_ips WHERE id = ?`, allowedIPID.Bytes()); err != nil {
		return fmt.Errorf("policies.RemoveAllowedIP: %w", err)
	}
	return s.writeAudit(ctx, p.TenantID, actor, "policy.allowed_ip.remove", "policy", &policyID, map[string]any{"cidr": cidr})
}

// ListAllowedIPs returns the AllowedIP rows for a policy, in stable order.
func (s *Service) ListAllowedIPs(ctx context.Context, policyID domain.ID) ([]AllowedIP, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, policy_id, cidr, COALESCE(description, ''), created_at
		FROM policy_allowed_ips
		WHERE policy_id = ?
		ORDER BY cidr ASC`,
		policyID.Bytes())
	if err != nil {
		return nil, fmt.Errorf("policies.ListAllowedIPs: %w", err)
	}
	defer rows.Close()
	var out []AllowedIP
	for rows.Next() {
		var (
			a           AllowedIP
			idBytes     []byte
			policyBytes []byte
		)
		if err := rows.Scan(&idBytes, &policyBytes, &a.CIDR, &a.Description, &a.CreatedAt); err != nil {
			return nil, err
		}
		if err := a.ID.Scan(idBytes); err != nil {
			return nil, err
		}
		if err := a.PolicyID.Scan(policyBytes); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// ----- Device assignment ---------------------------------------------------

// AssignToDevice points a device at a policy. Pass policyID = zero ID
// to unassign (devices.policy_id = NULL). The device's tenant must
// match the policy's tenant (or this returns an error).
func (s *Service) AssignToDevice(ctx context.Context, deviceID, policyID, actor domain.ID) error {
	if policyID.IsZero() {
		// Unassign path.
		// Existence by SELECT, for the same reason as Update above:
		// unassigning a device that has no policy changes nothing, so
		// RowsAffected is 0 and this returned ErrNotFound for a device
		// that exists. "Remove the policy" on an already-unbound device
		// is not an error — it is a no-op that already holds.
		var exists int
		if err := s.db.QueryRowContext(ctx,
			`SELECT 1 FROM devices WHERE id = ? AND deleted_at IS NULL`,
			deviceID.Bytes()).Scan(&exists); err != nil {
			return ErrNotFound
		}
		if _, err := s.db.ExecContext(ctx,
			`UPDATE devices SET policy_id = NULL WHERE id = ?`,
			deviceID.Bytes()); err != nil {
			return fmt.Errorf("policies.AssignToDevice unassign: %w", err)
		}
		// We don't have a tenantID here; we'd need a devices lookup, but
		// for the unassign-when-already-unassigned case the audit row is
		// optional. Skip rather than couple to internal/devices.
		return nil
	}

	// Assign path: validate tenant match.
	var deviceTenant, policyTenant []byte
	row := s.db.QueryRowContext(ctx, `
		SELECT d.tenant_id, p.tenant_id
		  FROM devices d, policies p
		 WHERE d.id = ? AND p.id = ? AND p.deleted_at IS NULL`,
		deviceID.Bytes(), policyID.Bytes())
	if err := row.Scan(&deviceTenant, &policyTenant); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		return fmt.Errorf("policies.AssignToDevice tenant lookup: %w", err)
	}
	if !bytesEqual(deviceTenant, policyTenant) {
		return errors.New("policies.AssignToDevice: device and policy belong to different tenants")
	}
	if _, err := s.db.ExecContext(ctx, `UPDATE devices SET policy_id = ? WHERE id = ?`, policyID.Bytes(), deviceID.Bytes()); err != nil {
		return fmt.Errorf("policies.AssignToDevice: %w", err)
	}
	var tenantID domain.ID
	_ = tenantID.Scan(deviceTenant)
	return s.writeAudit(ctx, tenantID, actor, "policy.assign", "device", &deviceID, map[string]any{"policy_id": policyID.String()})
}

// GetEffectiveAllowedIPs returns the selected policy's destination routes.
// Empty means no permitted destination; callers must never widen it to a default route.
func (s *Service) GetEffectiveAllowedIPs(ctx context.Context, deviceID domain.ID) ([]string, error) {
	// Static CIDRs and hostname-derived addresses are unioned here
	// (0.15.0). Everything downstream — the client's AllowedIPs, the
	// gateway's nftables ruleset — sees one flat list and never learns
	// that some entries came from DNS. That keeps hostname support out
	// of the enforcement path entirely, which is where you want it: the
	// gateway should not depend on name resolution to decide what to
	// permit.
	rows, err := s.db.QueryContext(ctx, `
		SELECT pai.cidr
		  FROM devices d
		  LEFT JOIN device_groups g ON g.id = d.group_id AND g.tenant_id = d.tenant_id AND g.deleted_at IS NULL
		  JOIN policies p ON p.id = COALESCE(d.policy_id, g.policy_id) AND p.tenant_id = d.tenant_id AND p.deleted_at IS NULL AND p.enabled = TRUE
		  JOIN policy_allowed_ips pai ON pai.policy_id = p.id
		 WHERE d.id = ?

		UNION

		SELECT CONCAT(INET6_NTOA(r.addr), '/', r.bits)
		  FROM devices d
		  LEFT JOIN device_groups g ON g.id = d.group_id AND g.tenant_id = d.tenant_id AND g.deleted_at IS NULL
		  JOIN policies p ON p.id = COALESCE(d.policy_id, g.policy_id) AND p.tenant_id = d.tenant_id AND p.deleted_at IS NULL AND p.enabled = TRUE
		  JOIN policy_hostnames h ON h.policy_id = p.id
		  JOIN policy_hostname_resolutions r ON r.hostname_id = h.id
		 WHERE d.id = ?

		UNION

		-- Virtual destinations, as /32. The phone routes these into the
		-- tunnel like any other line; the gateway is what makes them
		-- land somewhere real.
		--
		-- CAST to match pai.cidr's collation. A UNION over a stored
		-- column and a CONCAT() result failed with "Illegal mix of
		-- collations" — the built string carries the connection's
		-- default, the column carries the table's.
		SELECT CAST(CONCAT(vh.virtual_ip, '/32') AS CHAR CHARACTER SET utf8mb4) COLLATE utf8mb4_unicode_ci
		  FROM devices d
		  LEFT JOIN device_groups g ON g.id = d.group_id AND g.tenant_id = d.tenant_id AND g.deleted_at IS NULL
		  JOIN policies p ON p.id = COALESCE(d.policy_id, g.policy_id) AND p.tenant_id = d.tenant_id AND p.deleted_at IS NULL AND p.enabled = TRUE
		  JOIN policy_virtual_hosts vh ON vh.policy_id = p.id
		 WHERE d.id = ?

		 ORDER BY 1 ASC`,
		deviceID.Bytes(), deviceID.Bytes(), deviceID.Bytes())
	if err != nil {
		return nil, fmt.Errorf("policies.GetEffectiveAllowedIPs: %w", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var cidr string
		if err := rows.Scan(&cidr); err != nil {
			return nil, err
		}
		// Canonicalise so a hostname resolving to an address already
		// covered by a static CIDR doesn't produce a duplicate entry in
		// the client's AllowedIPs.
		if c, cerr := normalizeCIDR(cidr); cerr == nil {
			cidr = c
		}
		out = append(out, cidr)
	}
	return dedupe(out), rows.Err()
}

// dedupe removes repeats while preserving order.
func dedupe(in []string) []string {
	if len(in) < 2 {
		return in
	}
	seen := make(map[string]struct{}, len(in))
	out := in[:0]
	for _, v := range in {
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}

// DNSSettings is the resolver configuration pushed to a device.
type DNSSettings struct {
	// Servers are resolver addresses for VpnService.Builder.addDnsServer.
	Servers []string
	// SearchDomains are appended to short names.
	SearchDomains []string
}

// GetEffectiveDNS returns the DNS settings for the device's policy.
func (s *Service) GetEffectiveDNS(ctx context.Context, deviceID domain.ID) (DNSSettings, error) {
	var servers, search sql.NullString
	err := s.db.QueryRowContext(ctx, `
		SELECT p.dns_servers, p.dns_search_domains
		  FROM devices d
		  LEFT JOIN device_groups g ON g.id = d.group_id AND g.tenant_id = d.tenant_id AND g.deleted_at IS NULL
		  JOIN policies p
		    ON p.id = COALESCE(d.policy_id, g.policy_id) AND p.tenant_id = d.tenant_id AND p.deleted_at IS NULL AND p.enabled = TRUE
		 WHERE d.id = ?`,
		deviceID.Bytes()).Scan(&servers, &search)
	if errors.Is(err, sql.ErrNoRows) {
		return DNSSettings{}, nil
	}
	if err != nil {
		return DNSSettings{}, fmt.Errorf("policies.GetEffectiveDNS: %w", err)
	}
	return DNSSettings{
		Servers:       splitList(servers.String),
		SearchDomains: splitList(search.String),
	}, nil
}

func splitList(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// RouteScope controls what happens to traffic a policy does not permit.
//
// It is the second of the two axes that shape a tunnel; the first is the
// per-app filter on devices.app_filter_mode. Keeping them independent
// matters: "which apps" and "what happens to non-permitted traffic" are
// orthogonal questions, and collapsing them into one enum would produce
// a cross-product that grows every time either side gains a value.
type RouteScope string

const (
	// RouteScopePolicy is a split tunnel: only the policy's CIDRs are
	// routed into the tunnel; everything else uses the normal network.
	RouteScopePolicy RouteScope = "policy"
	// RouteScopeFull is lockdown: everything is routed into the tunnel
	// and the gateway drops whatever the policy doesn't permit, so the
	// selected apps reach the permitted servers and nothing else.
	RouteScopeFull RouteScope = "full"
)

// GetEffectiveRouteScope returns the route scope of the device's policy.
//
// Defaults to RouteScopePolicy for an unbound device. That default is the
// safe one in the sense that matters here: an unbound device is already
// refused by the client's deny-by-default check, and returning "full"
// would mean a misconfigured device that somehow did connect would lose
// all network access rather than merely failing to reach the hospital.
func (s *Service) GetEffectiveRouteScope(ctx context.Context, deviceID domain.ID) (RouteScope, error) {
	var scope string
	err := s.db.QueryRowContext(ctx, `
		SELECT p.route_scope
		  FROM devices d
		  LEFT JOIN device_groups g ON g.id = d.group_id AND g.tenant_id = d.tenant_id AND g.deleted_at IS NULL
		  JOIN policies p
		    ON p.id = COALESCE(d.policy_id, g.policy_id) AND p.tenant_id = d.tenant_id AND p.deleted_at IS NULL AND p.enabled = TRUE
		 WHERE d.id = ?`,
		deviceID.Bytes()).Scan(&scope)
	if errors.Is(err, sql.ErrNoRows) {
		return RouteScopePolicy, nil
	}
	if err != nil {
		return RouteScopePolicy, fmt.Errorf("policies.GetEffectiveRouteScope: %w", err)
	}
	switch RouteScope(scope) {
	case RouteScopeFull:
		return RouteScopeFull, nil
	default:
		// Unknown value from a newer schema: fall back to the narrower
		// behaviour rather than guessing our way into lockdown.
		return RouteScopePolicy, nil
	}
}

// IsDeviceBound reports whether the device is assigned to a policy that
// currently exists and is enabled.
//
// This is deliberately separate from GetEffectiveAllowedIPs returning a
// non-empty slice. A policy with zero CIDRs still counts as "bound" —
// the admin created it and attached the device, they just haven't added
// destinations yet (or removed them all). Collapsing the two would make
// "admin is mid-edit" indistinguishable from "device was never
// provisioned", and the client shows different guidance for each.
func (s *Service) IsDeviceBound(ctx context.Context, deviceID domain.ID) (bool, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `
		SELECT COUNT(*)
		  FROM devices d
		  LEFT JOIN device_groups g ON g.id = d.group_id AND g.tenant_id = d.tenant_id AND g.deleted_at IS NULL
		  JOIN policies p ON p.id = COALESCE(d.policy_id, g.policy_id) AND p.tenant_id = d.tenant_id
		 WHERE d.id = ?
		   AND p.deleted_at IS NULL
		   AND p.enabled = TRUE`,
		deviceID.Bytes()).Scan(&n)
	if err != nil {
		return false, fmt.Errorf("policies.IsDeviceBound: %w", err)
	}
	return n > 0, nil
}

// ----- helpers -------------------------------------------------------------

// normalizeCIDR validates the input and returns the canonical masked form.
// "10.10.0.5/16" → "10.10.0.0/16". Both v4 and v6 are accepted.
func normalizeCIDR(s string) (string, error) {
	prefix, err := netip.ParsePrefix(strings.TrimSpace(s))
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrInvalidCIDR, err)
	}
	return prefix.Masked().String(), nil
}

func nullStr(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanPolicy(r rowScanner) (*Policy, error) {
	var p Policy
	var idBytes, tenantBytes []byte
	err := r.Scan(&idBytes, &tenantBytes, &p.Name, &p.Description, &p.Enabled, &p.SourceNAT, &p.EndpointMode, &p.ControlChannel, &p.Precedence,
		&p.CreatedAt, &p.UpdatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("scanPolicy: %w", err)
	}
	if err := p.ID.Scan(idBytes); err != nil {
		return nil, err
	}
	if err := p.TenantID.Scan(tenantBytes); err != nil {
		return nil, err
	}
	return &p, nil
}

func (s *Service) writeAudit(ctx context.Context, tenantID, actor domain.ID, action, targetKind string, targetID *domain.ID, details map[string]any) error {
	entry := audit.Entry{
		TenantID:   tenantID,
		ActorKind:  audit.ActorUser,
		Action:     action,
		TargetKind: targetKind,
		TargetID:   targetID,
		Details:    details,
	}
	if !actor.IsZero() {
		entry.ActorID = &actor
	}
	if err := s.audit.Append(ctx, entry); err != nil {
		return fmt.Errorf("policies audit: %w", err)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Virtual destinations.
//
// The phone is told virtual_ip; the gateway rewrites it to real_ip. The
// real address never reaches the handset.

type VirtualHost struct {
	ID          domain.ID
	PolicyID    domain.ID
	VirtualIP   string
	RealIP      string
	Description string
}

// virtualRange is where virtual destinations must live. Outside the
// device pool by construction — see migration 0024.
const virtualRange = "10.79.0.0/16"

func (s *Service) AddVirtualHost(
	ctx context.Context, policyID, actor domain.ID,
	virtualIP, realIP, description string,
) (*VirtualHost, error) {
	v, err := netip.ParseAddr(virtualIP)
	if err != nil {
		return nil, fmt.Errorf("가상 주소가 올바르지 않습니다: %w", err)
	}
	r, err := netip.ParseAddr(realIP)
	if err != nil {
		return nil, fmt.Errorf("진짜 주소가 올바르지 않습니다: %w", err)
	}
	if !netip.MustParsePrefix(virtualRange).Contains(v) {
		// Refuse rather than warn. A virtual address inside the device
		// pool works today and collides on some future enrolment, which
		// is the worst shape a defect can take.
		return nil, fmt.Errorf("가상 주소는 %s 안에 있어야 합니다 (폰 주소 대역과 겹치지 않도록)", virtualRange)
	}
	if netip.MustParsePrefix(virtualRange).Contains(r) {
		return nil, fmt.Errorf("진짜 주소가 가상 대역 안에 있습니다 — 서버가 실제로 갖는 주소를 적으세요")
	}

	p, err := s.Get(ctx, policyID)
	if err != nil {
		return nil, err
	}
	id := domain.NewID()
	if _, err := s.db.ExecContext(ctx, `
		INSERT INTO policy_virtual_hosts (id, policy_id, virtual_ip, real_ip, description)
		VALUES (?, ?, ?, ?, ?)`,
		id.Bytes(), policyID.Bytes(), v.String(), r.String(),
		sql.NullString{String: description, Valid: description != ""}); err != nil {
		return nil, fmt.Errorf("policies.AddVirtualHost: %w", err)
	}
	_ = s.writeAudit(ctx, p.TenantID, actor, "policy.virtual_host.add", "policy", &policyID,
		map[string]any{"virtual_ip": v.String(), "real_ip": r.String()})
	return &VirtualHost{ID: id, PolicyID: policyID, VirtualIP: v.String(), RealIP: r.String(), Description: description}, nil
}

func (s *Service) RemoveVirtualHost(ctx context.Context, policyID, hostID, actor domain.ID) error {
	p, err := s.Get(ctx, policyID)
	if err != nil {
		return err
	}
	if _, err := s.db.ExecContext(ctx, `
		DELETE FROM policy_virtual_hosts WHERE id = ? AND policy_id = ?`,
		hostID.Bytes(), policyID.Bytes()); err != nil {
		return fmt.Errorf("policies.RemoveVirtualHost: %w", err)
	}
	_ = s.writeAudit(ctx, p.TenantID, actor, "policy.virtual_host.remove", "policy", &policyID,
		map[string]any{"host_id": hostID.String()})
	return nil
}

func (s *Service) ListVirtualHosts(ctx context.Context, policyID domain.ID) ([]VirtualHost, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, policy_id, virtual_ip, real_ip, COALESCE(description, '')
		  FROM policy_virtual_hosts WHERE policy_id = ? ORDER BY virtual_ip`, policyID.Bytes())
	if err != nil {
		return nil, fmt.Errorf("policies.ListVirtualHosts: %w", err)
	}
	defer rows.Close()
	var out []VirtualHost
	for rows.Next() {
		var h VirtualHost
		var idB, polB []byte
		if err := rows.Scan(&idB, &polB, &h.VirtualIP, &h.RealIP, &h.Description); err != nil {
			return nil, err
		}
		_ = h.ID.Scan(idB)
		_ = h.PolicyID.Scan(polB)
		out = append(out, h)
	}
	return out, rows.Err()
}

// VirtualHostsForDevice is what the gateway needs: every rewrite that
// applies to this device, keyed by its policy.
func (s *Service) VirtualHostsForDevice(ctx context.Context, deviceID domain.ID) ([]VirtualHost, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT vh.id, vh.policy_id, vh.virtual_ip, vh.real_ip, COALESCE(vh.description, '')
		  FROM devices d
		  LEFT JOIN device_groups g ON g.id = d.group_id AND g.tenant_id = d.tenant_id AND g.deleted_at IS NULL
		  JOIN policies p ON p.id = COALESCE(d.policy_id, g.policy_id) AND p.tenant_id = d.tenant_id AND p.deleted_at IS NULL AND p.enabled = TRUE
		  JOIN policy_virtual_hosts vh ON vh.policy_id = p.id
		 WHERE d.id = ?`, deviceID.Bytes())
	if err != nil {
		return nil, fmt.Errorf("policies.VirtualHostsForDevice: %w", err)
	}
	defer rows.Close()
	var out []VirtualHost
	for rows.Next() {
		var h VirtualHost
		var idB, polB []byte
		if err := rows.Scan(&idB, &polB, &h.VirtualIP, &h.RealIP, &h.Description); err != nil {
			return nil, err
		}
		_ = h.ID.Scan(idB)
		_ = h.PolicyID.Scan(polB)
		out = append(out, h)
	}
	return out, rows.Err()
}
