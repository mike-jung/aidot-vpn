package policies

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"github.com/aidotvpn/server/internal/domain"
)

// Admin-facing surface for the settings added in 0.11.0–0.15.0.
//
// Those releases added route scope, DNS push and hostname rules to the
// schema and the enforcement path, but never to the API — so every one of
// them was configurable only by editing the database directly. Five
// releases of policy surface with no way for an admin to reach it is its
// own kind of gap, and this file closes it.

// Hostname is one row of policy_hostnames plus its current resolutions.
type Hostname struct {
	ID          domain.ID
	PolicyID    domain.ID
	Hostname    string
	Description string
	// GuardCIDR bounds what a resolution may return. Empty means no
	// bound, which the console flags as unsafe — see the migration
	// comment for why that matters.
	GuardCIDR string
	// Resolved is the addresses currently in effect, newest resolution
	// first. Populated by ListHostnames.
	Resolved []string
}

// ErrInvalidHostname is returned for a syntactically unusable name.
var ErrInvalidHostname = errors.New("invalid hostname")

// AddHostname attaches a hostname rule to a policy.
func (s *Service) AddHostname(
	ctx context.Context,
	policyID, actor domain.ID,
	hostname, guardCIDR, description string,
) (*Hostname, error) {
	hostname = strings.TrimSpace(strings.ToLower(hostname))
	if err := validateHostname(hostname); err != nil {
		return nil, err
	}

	guard := strings.TrimSpace(guardCIDR)
	if guard != "" {
		canonical, err := normalizeCIDR(guard)
		if err != nil {
			return nil, fmt.Errorf("guard_cidr: %w", err)
		}
		guard = canonical
	}

	p, err := s.Get(ctx, policyID)
	if err != nil {
		return nil, err
	}

	id := domain.NewID()
	if _, err := s.db.ExecContext(ctx, `
		INSERT INTO policy_hostnames (id, policy_id, hostname, guard_cidr, description)
		VALUES (?, ?, ?, ?, ?)`,
		id.Bytes(), policyID.Bytes(), hostname, nullStr(guard), nullStr(description)); err != nil {
		return nil, fmt.Errorf("policies.AddHostname: %w", err)
	}

	h := &Hostname{
		ID: id, PolicyID: policyID, Hostname: hostname,
		GuardCIDR: guard, Description: description,
	}
	// Audit records the guard explicitly. "Who removed the bound on this
	// hostname" is exactly the question you want answerable after an
	// incident, and it is invisible in a diff of resolved addresses.
	_ = s.writeAudit(ctx, p.TenantID, actor, "policy.hostname.add", "policy", &policyID,
		map[string]any{"hostname": hostname, "guard_cidr": guard})
	return h, nil
}

// RemoveHostname detaches a hostname rule. Its resolutions cascade.
func (s *Service) RemoveHostname(ctx context.Context, policyID, hostnameID, actor domain.ID) error {
	p, err := s.Get(ctx, policyID)
	if err != nil {
		return err
	}
	res, err := s.db.ExecContext(ctx, `
		DELETE FROM policy_hostnames WHERE id = ? AND policy_id = ?`,
		hostnameID.Bytes(), policyID.Bytes())
	if err != nil {
		return fmt.Errorf("policies.RemoveHostname: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return s.writeAudit(ctx, p.TenantID, actor, "policy.hostname.remove", "policy", &policyID,
		map[string]any{"hostname_id": hostnameID.String()})
}

// ListHostnames returns a policy's hostname rules with their current
// resolutions.
//
// The resolutions are included because an admin looking at this screen is
// almost always asking "did that name resolve, and to what?" — the answer
// otherwise lives only in the controller's logs.
func (s *Service) ListHostnames(ctx context.Context, policyID domain.ID) ([]Hostname, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT h.id, h.hostname, COALESCE(h.guard_cidr, ''), COALESCE(h.description, '')
		  FROM policy_hostnames h
		 WHERE h.policy_id = ?
		 ORDER BY h.hostname ASC`,
		policyID.Bytes())
	if err != nil {
		return nil, fmt.Errorf("policies.ListHostnames: %w", err)
	}
	defer rows.Close()

	var out []Hostname
	for rows.Next() {
		var (
			idB []byte
			h   Hostname
		)
		if err := rows.Scan(&idB, &h.Hostname, &h.GuardCIDR, &h.Description); err != nil {
			return nil, err
		}
		if err := h.ID.Scan(idB); err != nil {
			continue
		}
		h.PolicyID = policyID
		out = append(out, h)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	for i := range out {
		addrs, err := s.resolutionsFor(ctx, out[i].ID)
		if err != nil {
			return nil, err
		}
		out[i].Resolved = addrs
	}
	return out, nil
}

func (s *Service) resolutionsFor(ctx context.Context, hostnameID domain.ID) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT CONCAT(INET6_NTOA(addr), '/', bits)
		  FROM policy_hostname_resolutions
		 WHERE hostname_id = ?
		 ORDER BY last_seen_at DESC`,
		hostnameID.Bytes())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var c string
		if err := rows.Scan(&c); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// Settings is the tunnel-shaping configuration on a policy.
type Settings struct {
	RouteScope    RouteScope
	DNSServers    []string
	SearchDomains []string
}

// GetSettings reads a policy's route scope and DNS configuration.
func (s *Service) GetSettings(ctx context.Context, policyID domain.ID) (Settings, error) {
	var (
		scope   string
		servers sql.NullString
		search  sql.NullString
	)
	err := s.db.QueryRowContext(ctx, `
		SELECT route_scope, dns_servers, dns_search_domains
		  FROM policies WHERE id = ? AND deleted_at IS NULL`,
		policyID.Bytes()).Scan(&scope, &servers, &search)
	if err != nil {
		return Settings{}, fmt.Errorf("policies.GetSettings: %w", err)
	}
	sc := RouteScope(scope)
	if sc != RouteScopeFull {
		sc = RouteScopePolicy
	}
	return Settings{
		RouteScope:    sc,
		DNSServers:    splitList(servers.String),
		SearchDomains: splitList(search.String),
	}, nil
}

// UpdateSettings writes route scope and DNS configuration.
//
// Validates DNS servers as literal addresses rather than accepting names:
// a resolver referenced by hostname would need resolving to be reached,
// which is circular, and the failure only shows up on a phone.
func (s *Service) UpdateSettings(
	ctx context.Context,
	policyID, actor domain.ID,
	st Settings,
) error {
	p, err := s.Get(ctx, policyID)
	if err != nil {
		return err
	}

	scope := st.RouteScope
	if scope != RouteScopeFull {
		scope = RouteScopePolicy
	}

	clean := make([]string, 0, len(st.DNSServers))
	for _, raw := range st.DNSServers {
		v := strings.TrimSpace(raw)
		if v == "" {
			continue
		}
		if _, perr := netip.ParseAddr(v); perr != nil {
			return fmt.Errorf("dns server %q must be a literal IP address, not a hostname", v)
		}
		clean = append(clean, v)
	}

	domains := make([]string, 0, len(st.SearchDomains))
	for _, raw := range st.SearchDomains {
		v := strings.TrimSpace(strings.ToLower(raw))
		if v == "" {
			continue
		}
		if err := validateHostname(v); err != nil {
			return fmt.Errorf("search domain %q: %w", v, err)
		}
		domains = append(domains, v)
	}

	if _, err := s.db.ExecContext(ctx, `
		UPDATE policies
		   SET route_scope = ?, dns_servers = ?, dns_search_domains = ?
		 WHERE id = ? AND deleted_at IS NULL`,
		string(scope), nullStr(strings.Join(clean, ",")),
		nullStr(strings.Join(domains, ",")), policyID.Bytes()); err != nil {
		return fmt.Errorf("policies.UpdateSettings: %w", err)
	}

	return s.writeAudit(ctx, p.TenantID, actor, "policy.settings.update", "policy", &policyID,
		map[string]any{
			"route_scope":        string(scope),
			"dns_servers":        clean,
			"dns_search_domains": domains,
		})
}

// validateHostname performs a syntactic check only. We do NOT require the
// name to resolve at creation time: an admin frequently adds the rule
// before the server exists, and refusing would force them to sequence
// their work around us.
func validateHostname(h string) error {
	if h == "" {
		return fmt.Errorf("%w: empty", ErrInvalidHostname)
	}
	if len(h) > 253 {
		return fmt.Errorf("%w: longer than 253 characters", ErrInvalidHostname)
	}
	if strings.HasPrefix(h, ".") || strings.HasSuffix(h, ".") {
		return fmt.Errorf("%w: leading or trailing dot", ErrInvalidHostname)
	}
	if strings.Contains(h, "..") {
		return fmt.Errorf("%w: empty label", ErrInvalidHostname)
	}
	// A wildcard cannot be resolved to an address, so accepting one would
	// create a rule that silently never matches anything.
	if strings.ContainsAny(h, "*?/ ") {
		return fmt.Errorf("%w: wildcards and paths are not supported", ErrInvalidHostname)
	}
	for _, label := range strings.Split(h, ".") {
		if len(label) > 63 {
			return fmt.Errorf("%w: label longer than 63 characters", ErrInvalidHostname)
		}
		if strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return fmt.Errorf("%w: label starts or ends with a hyphen", ErrInvalidHostname)
		}
		for _, r := range label {
			isAlnum := (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9')
			if !isAlnum && r != '-' {
				return fmt.Errorf("%w: invalid character %q", ErrInvalidHostname, r)
			}
		}
	}
	return nil
}
