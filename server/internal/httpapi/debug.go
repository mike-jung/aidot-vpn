package httpapi

import (
	"net/http"
	"strings"

	"github.com/aidotvpn/server/internal/domain"
	"github.com/aidotvpn/server/internal/policies"
)

// GET /devices/{id}/effective — what this device would receive right now.
//
// Added in 0.26.0 for the tutorial, and useful well beyond it.
//
// Everything a device actually gets — its permitted CIDRs, route scope,
// DNS servers, per-app filter — is assembled at registration time and
// then only visible in the registration response, which nobody can see
// after the fact. So the most common question while learning the system
// ("I changed the policy, did it reach the phone?") had no answer short
// of re-registering and reading the JSON, or querying the database by
// hand.
//
// This endpoint answers it directly, and it answers with the SAME
// resolution path registration uses rather than re-deriving it. If the
// two ever disagreed, this screen would be worse than nothing: it would
// confidently report a configuration the device does not have.
//
// Read-only and tenant-scoped. Not admin-only: a user checking their own
// device's configuration is exactly who needs it most, and it exposes
// nothing they cannot already infer by connecting.
func (a *API) registerDebugRoutes(mux *http.ServeMux) {
	mux.Handle("GET /devices/{id}/effective",
		a.requireAuth(http.HandlerFunc(a.deviceEffective)))
}

type effectiveJSON struct {
	DeviceID    string `json:"device_id"`
	DisplayName string `json:"display_name"`
	Status      string `json:"status"`

	// PolicyBound is the single most important field here. False means
	// the device reaches nothing, and it is the most common reason a
	// tutorial reader's tunnel "connects but does not work".
	PolicyBound bool   `json:"policy_bound"`
	PolicyName  string `json:"policy_name,omitempty"`

	// AllowedIPs is what the client routes into the tunnel, resolver
	// addresses included.
	AllowedIPs []string `json:"allowed_ips"`
	// Hostnames shows which of those came from a hostname rule and what
	// each resolved to — the part that is otherwise invisible.
	Hostnames []effectiveHostname `json:"hostnames"`

	RouteScope       string   `json:"route_scope"`
	RouteScopeMeans  string   `json:"route_scope_means"`
	DNSServers       []string `json:"dns_servers"`
	DNSSearchDomains []string `json:"dns_search_domains"`

	AppFilterMode     string   `json:"app_filter_mode"`
	AppFilterMeans    string   `json:"app_filter_means"`
	AppFilterPackages []string `json:"app_filter_packages"`

	DeploymentMode string `json:"deployment_mode"`
	HostPackage    string `json:"host_package,omitempty"`

	// Warnings are the conditions that make a tunnel behave in a way
	// that surprises people. Plain sentences, not codes: this is read by
	// someone learning the system, and "policy_unbound" would send them
	// back to the documentation.
	Warnings []string `json:"warnings"`
}

type effectiveHostname struct {
	Hostname  string   `json:"hostname"`
	GuardCIDR string   `json:"guard_cidr,omitempty"`
	Resolved  []string `json:"resolved"`
}

func (a *API) deviceEffective(w http.ResponseWriter, r *http.Request) {
	u := userFromContext(r.Context())
	id, err := parseHexID(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid device id")
		return
	}

	owns, err := a.ownsDevice(r, id)
	if err != nil {
		a.serverError(w, "effective: ownership", err)
		return
	}
	if !owns {
		writeError(w, http.StatusNotFound, "device not found")
		return
	}

	dev, err := a.cfg.Devices.Get(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusNotFound, "device not found")
		return
	}

	// Same calls registration makes. Re-deriving would risk this screen
	// disagreeing with reality.
	allowedIPs, bound, err := a.effectivePolicy(r.Context(), id)
	if err != nil {
		a.serverError(w, "effective: policy", err)
		return
	}
	routeScope, err := a.routeScopeFor(r.Context(), id)
	if err != nil {
		a.serverError(w, "effective: route scope", err)
		return
	}
	dns, allowedIPs, err := a.dnsFor(r.Context(), id, allowedIPs)
	if err != nil {
		a.serverError(w, "effective: dns", err)
		return
	}

	out := effectiveJSON{
		DeviceID:          id.String(),
		DisplayName:       dev.DisplayName,
		Status:            string(dev.Status),
		PolicyBound:       bound,
		AllowedIPs:        orEmpty(allowedIPs),
		RouteScope:        routeScope,
		DNSServers:        orEmpty(dns.Servers),
		DNSSearchDomains:  orEmpty(dns.SearchDomains),
		AppFilterMode:     string(dev.AppFilter.Mode),
		AppFilterPackages: orEmpty(dev.AppFilter.Packages),
		DeploymentMode:    deploymentModeOrDefault(dev.DeploymentMode),
		HostPackage:       dev.HostPackage,
		Hostnames:         []effectiveHostname{},
		Warnings:          []string{},
	}
	if out.AppFilterMode == "" {
		out.AppFilterMode = "off"
	}

	// Plain-language explanations. The enum values are precise and
	// meaningless to a reader who has not internalised the two axes.
	switch routeScope {
	case string(policies.RouteScopeFull):
		out.RouteScopeMeans = "잠금 — 모든 트래픽이 터널로 들어가고, 허용 목록 밖은 차단됩니다 (인터넷 포함)"
	default:
		out.RouteScopeMeans = "스플릿 — 허용 목록만 터널로 가고, 나머지는 평소 네트워크를 씁니다"
	}
	switch out.AppFilterMode {
	case "include":
		out.AppFilterMeans = "지정한 앱만 터널을 사용합니다"
	case "exclude":
		out.AppFilterMeans = "지정한 앱을 제외한 모든 앱이 터널을 사용합니다"
	default:
		out.AppFilterMeans = "단말의 모든 앱이 터널을 사용합니다"
	}

	// The policy id is not on the Device struct, so read it directly.
	// Best-effort: the name and hostname list are for display, and a
	// failure here must not turn a diagnostic screen into a 500 — the
	// fields above are the ones that matter.
	var policyIDBytes []byte
	if err := a.cfg.DB.QueryRowContext(r.Context(),
		`SELECT policy_id FROM devices WHERE id = ?`, id.Bytes()).Scan(&policyIDBytes); err == nil &&
		len(policyIDBytes) > 0 {
		var pid domain.ID
		if pid.Scan(policyIDBytes) == nil {
			if p, perr := a.cfg.Policies.Get(r.Context(), pid); perr == nil {
				out.PolicyName = p.Name
			}
			if hosts, herr := a.cfg.Policies.ListHostnames(r.Context(), pid); herr == nil {
				for i := range hosts {
					out.Hostnames = append(out.Hostnames, effectiveHostname{
						Hostname:  hosts[i].Hostname,
						GuardCIDR: hosts[i].GuardCIDR,
						Resolved:  orEmpty(hosts[i].Resolved),
					})
				}
			}
		}
	}

	out.Warnings = effectiveWarnings(out, u.TenantID.String())
	writeJSON(w, http.StatusOK, out)
}

// effectiveWarnings names the configurations that behave in ways people
// do not expect. Each one corresponds to a support question this project
// has actually produced.
func effectiveWarnings(e effectiveJSON, _ string) []string {
	var w []string

	if !e.PolicyBound {
		w = append(w, "정책이 지정되지 않았습니다. 이 단말은 연결 자체가 거부되며, "+
			"관리자 화면에서 정책을 할당해야 합니다.")
	}
	if e.Status != "active" {
		w = append(w, "단말 상태가 active 가 아닙니다("+e.Status+"). "+
			"게이트웨이가 WireGuard 피어를 설치하지 않아 연결되지 않습니다.")
	}
	if e.PolicyBound && len(e.AllowedIPs) == 0 {
		w = append(w, "허용된 주소가 하나도 없습니다. 터널은 열리지만 아무 곳에도 갈 수 없습니다.")
	}
	// The Android DNS-capture footgun.
	if len(e.DNSServers) > 0 && e.RouteScope != string(policies.RouteScopeFull) &&
		e.AppFilterMode == "off" {
		w = append(w, "스플릿 터널 + 앱 필터 off + DNS 푸시 조합입니다. "+
			"안드로이드는 VPN 의 DNS 를 단말 전체에 적용하므로, 이 리졸버가 공인 도메인을 "+
			"해석하지 못하면 인터넷 이름 조회가 끊깁니다. 앱 필터를 include 로 바꾸거나 "+
			"포워딩 리졸버를 쓰세요.")
	}
	if e.RouteScope == string(policies.RouteScopeFull) {
		w = append(w, "잠금 모드입니다. 이 단말은 허용 목록 밖으로는 인터넷도 나갈 수 없습니다.")
	}
	if e.AppFilterMode == "include" && len(e.AppFilterPackages) == 0 {
		w = append(w, "앱 필터가 include 인데 대상 앱이 비어 있습니다. "+
			"클라이언트는 연결을 거부합니다.")
	}
	for _, h := range e.Hostnames {
		if len(h.Resolved) == 0 {
			w = append(w, "호스트명 "+h.Hostname+" 이 아직 해석되지 않았습니다. "+
				"컨트롤러 로그의 resolver 항목을 확인하세요.")
		}
		if h.GuardCIDR == "" {
			w = append(w, "호스트명 "+h.Hostname+" 에 허용 범위(guard)가 없습니다. "+
				"DNS 답변을 조작할 수 있는 쪽이 접근 권한을 정하게 됩니다.")
		}
	}
	if len(w) == 0 {
		w = append(w, "특이사항 없습니다.")
	}
	return w
}

var _ = strings.TrimSpace
