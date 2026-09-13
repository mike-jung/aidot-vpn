package httpapi

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/aidotvpn/server/internal/policies"
)

// Admin endpoints for the policy surface added between 0.11.0 and 0.15.0.
//
// All of it — route scope, DNS push, hostname rules — was reachable only
// by editing the database until now. These routes are admin-only for the
// same reason policy CRUD is: they decide what a device can reach, and a
// user able to widen their own policy makes the gateway enforcement
// pointless.

func (a *API) registerPolicyAdminRoutes(mux *http.ServeMux) {
	mux.Handle("GET /policies/{id}/settings",
		a.requireAuth(http.HandlerFunc(a.getPolicySettings)))
	mux.Handle("PUT /policies/{id}/settings",
		a.requireAuth(a.requireAdmin(http.HandlerFunc(a.updatePolicySettings))))

	mux.Handle("GET /policies/{id}/hostnames",
		a.requireAuth(http.HandlerFunc(a.listPolicyHostnames)))
	mux.Handle("POST /policies/{id}/hostnames",
		a.requireAuth(a.requireAdmin(http.HandlerFunc(a.addPolicyHostname))))
	mux.Handle("DELETE /policies/{id}/hostnames/{hostnameId}",
		a.requireAuth(a.requireAdmin(http.HandlerFunc(a.removePolicyHostname))))
}

type policySettingsJSON struct {
	RouteScope    string   `json:"route_scope"`
	DNSServers    []string `json:"dns_servers"`
	SearchDomains []string `json:"dns_search_domains"`

	// DNSScopeWarning is set when the combination of this policy's route
	// scope and the attached devices' app filters would send the whole
	// device's DNS to an internal resolver.
	//
	// Surfaced in the API rather than left to the console so that anyone
	// driving this by script gets the same warning. It is advisory: some
	// sites run a forwarding resolver and the combination is fine for
	// them, so we do not refuse it.
	DNSScopeWarning string `json:"dns_scope_warning,omitempty"`
}

func (a *API) getPolicySettings(w http.ResponseWriter, r *http.Request) {
	u := userFromContext(r.Context())
	id, err := parseHexID(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid policy id")
		return
	}
	p, err := a.cfg.Policies.Get(r.Context(), id)
	if err != nil {
		a.policyLookupError(w, err)
		return
	}
	if p.TenantID != u.TenantID {
		writeError(w, http.StatusNotFound, "policy not found")
		return
	}
	st, err := a.cfg.Policies.GetSettings(r.Context(), id)
	if err != nil {
		a.serverError(w, "get policy settings", err)
		return
	}
	out := policySettingsJSON{
		RouteScope:    string(st.RouteScope),
		DNSServers:    orEmpty(st.DNSServers),
		SearchDomains: orEmpty(st.SearchDomains),
	}
	out.DNSScopeWarning = a.dnsScopeWarning(r, id, st)
	writeJSON(w, http.StatusOK, out)
}

func (a *API) updatePolicySettings(w http.ResponseWriter, r *http.Request) {
	u := userFromContext(r.Context())
	id, err := parseHexID(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid policy id")
		return
	}
	p, err := a.cfg.Policies.Get(r.Context(), id)
	if err != nil {
		a.policyLookupError(w, err)
		return
	}
	if p.TenantID != u.TenantID {
		writeError(w, http.StatusNotFound, "policy not found")
		return
	}

	var body struct {
		RouteScope    string   `json:"route_scope"`
		DNSServers    []string `json:"dns_servers"`
		SearchDomains []string `json:"dns_search_domains"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	st := policies.Settings{
		RouteScope:    policies.RouteScope(body.RouteScope),
		DNSServers:    body.DNSServers,
		SearchDomains: body.SearchDomains,
	}
	if err := a.cfg.Policies.UpdateSettings(r.Context(), id, u.ID, st); err != nil {
		// Validation failures here are admin typos (a hostname where an
		// IP belongs), not server faults.
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	fresh, err := a.cfg.Policies.GetSettings(r.Context(), id)
	if err != nil {
		a.serverError(w, "reload policy settings", err)
		return
	}
	out := policySettingsJSON{
		RouteScope:    string(fresh.RouteScope),
		DNSServers:    orEmpty(fresh.DNSServers),
		SearchDomains: orEmpty(fresh.SearchDomains),
	}
	out.DNSScopeWarning = a.dnsScopeWarning(r, id, fresh)
	writeJSON(w, http.StatusOK, out)
}

// dnsScopeWarning reports the Android DNS-capture footgun when it applies.
//
// Android applies a VPN's DNS servers to every app on the VPN network,
// not only to traffic matching the tunnel's routes. So a split tunnel over
// the whole device plus an internal-only resolver captures all of the
// device's DNS, and public names stop resolving while the device looks
// connected.
func (a *API) dnsScopeWarning(r *http.Request, policyID interface{ Bytes() []byte }, st policies.Settings) string {
	if len(st.DNSServers) == 0 || st.RouteScope == policies.RouteScopeFull {
		return ""
	}
	// Only devices left on app_filter_mode='off' are affected; an
	// 'include' filter confines the resolver to the listed apps.
	var n int
	err := a.cfg.DB.QueryRowContext(r.Context(), `
		SELECT COUNT(*) FROM devices
		 WHERE policy_id = ? AND deleted_at IS NULL
		   AND (app_filter_mode IS NULL OR app_filter_mode = 'off')`,
		policyID.Bytes()).Scan(&n)
	if err != nil || n == 0 {
		return ""
	}
	return "이 정책은 스플릿 터널이며 DNS 서버를 푸시합니다. " +
		"앱 필터가 'off'인 단말이 " + itoa(n) + "대 있어, 해당 단말의 " +
		"모든 DNS 조회가 이 리졸버로 갑니다. 리졸버가 공인 도메인을 " +
		"해석하지 못하면 인터넷 이름 해석이 끊깁니다. 앱 필터를 " +
		"'include'로 바꾸거나 포워딩 리졸버를 사용하세요."
}

type hostnameJSON struct {
	ID          string   `json:"id"`
	Hostname    string   `json:"hostname"`
	GuardCIDR   string   `json:"guard_cidr,omitempty"`
	Description string   `json:"description,omitempty"`
	Resolved    []string `json:"resolved"`
	// Unguarded flags a rule with no guard_cidr so the console can mark
	// it without re-deriving the condition.
	Unguarded bool `json:"unguarded"`
}

func (a *API) listPolicyHostnames(w http.ResponseWriter, r *http.Request) {
	u := userFromContext(r.Context())
	id, err := parseHexID(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid policy id")
		return
	}
	p, err := a.cfg.Policies.Get(r.Context(), id)
	if err != nil {
		a.policyLookupError(w, err)
		return
	}
	if p.TenantID != u.TenantID {
		writeError(w, http.StatusNotFound, "policy not found")
		return
	}
	hosts, err := a.cfg.Policies.ListHostnames(r.Context(), id)
	if err != nil {
		a.serverError(w, "list hostnames", err)
		return
	}
	out := make([]hostnameJSON, 0, len(hosts))
	for i := range hosts {
		out = append(out, toHostnameJSON(&hosts[i]))
	}
	writeJSON(w, http.StatusOK, map[string]any{"hostnames": out})
}

func (a *API) addPolicyHostname(w http.ResponseWriter, r *http.Request) {
	u := userFromContext(r.Context())
	id, err := parseHexID(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid policy id")
		return
	}
	p, err := a.cfg.Policies.Get(r.Context(), id)
	if err != nil {
		a.policyLookupError(w, err)
		return
	}
	if p.TenantID != u.TenantID {
		writeError(w, http.StatusNotFound, "policy not found")
		return
	}
	var body struct {
		Hostname    string `json:"hostname"`
		GuardCIDR   string `json:"guard_cidr"`
		Description string `json:"description"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	h, err := a.cfg.Policies.AddHostname(
		r.Context(), id, u.ID, body.Hostname, body.GuardCIDR, body.Description)
	if err != nil {
		if errors.Is(err, policies.ErrInvalidHostname) ||
			errors.Is(err, policies.ErrInvalidCIDR) {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		a.serverError(w, "add hostname", err)
		return
	}
	writeJSON(w, http.StatusCreated, toHostnameJSON(h))
}

func (a *API) removePolicyHostname(w http.ResponseWriter, r *http.Request) {
	u := userFromContext(r.Context())
	id, err := parseHexID(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid policy id")
		return
	}
	hid, err := parseHexID(r.PathValue("hostnameId"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid hostname id")
		return
	}
	p, err := a.cfg.Policies.Get(r.Context(), id)
	if err != nil {
		a.policyLookupError(w, err)
		return
	}
	if p.TenantID != u.TenantID {
		writeError(w, http.StatusNotFound, "policy not found")
		return
	}
	if err := a.cfg.Policies.RemoveHostname(r.Context(), id, hid, u.ID); err != nil {
		if errors.Is(err, policies.ErrNotFound) {
			writeError(w, http.StatusNotFound, "hostname not found")
			return
		}
		a.serverError(w, "remove hostname", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func toHostnameJSON(h *policies.Hostname) hostnameJSON {
	return hostnameJSON{
		ID:          h.ID.String(),
		Hostname:    h.Hostname,
		GuardCIDR:   h.GuardCIDR,
		Description: h.Description,
		Resolved:    orEmpty(h.Resolved),
		Unguarded:   h.GuardCIDR == "",
	}
}

func (a *API) policyLookupError(w http.ResponseWriter, err error) {
	if errors.Is(err, policies.ErrNotFound) {
		writeError(w, http.StatusNotFound, "policy not found")
		return
	}
	a.serverError(w, "get policy", err)
}

// orEmpty makes a nil slice serialise as [] rather than null, so the
// console can iterate without a guard on every field.
func orEmpty(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
