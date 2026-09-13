package httpapi

import (
	"net/http"
)

// The reach map: which devices, through which policy, to which CIDRs.
//
// ## Why not the topology every other console draws
//
// NetBird and Tailscale draw peers connected to peers, because they are
// meshes and A-B is a meaningful line. Everything here goes through the
// gateway, so that drawing is one star and says nothing.
//
// The questions an admin actually has are about *reach*, and each one
// currently needs several screens and a comparison done in the head:
//
//	이 정책이 여는 대역이 어디인가      정책 화면에서 목록을 읽음
//	두 정책이 겹치나                   두 화면을 열어 눈으로 비교
//	아무도 안 쓰는 대역이 있나          알 방법 없음
//	이 대역에 갈 수 있는 폰이 몇 대인가  디바이스 목록을 세어봄
//
// A bipartite graph — device groups on one side, CIDRs on the other,
// policies as the edges — answers all four at a glance.
//
// ## Overlap and orphans are computed here, not in the browser
//
// The console could intersect the CIDRs itself, but prefix arithmetic
// belongs where the addresses are already parsed. Doing it in JavaScript
// would mean a second implementation of subnet containment, and the two
// would drift.
func (a *API) registerReachRoute(mux *http.ServeMux) {
	mux.Handle("GET /reach", a.requireAuth(a.requireAdmin(http.HandlerFunc(a.reachMap))))
}

func (a *API) reachMap(w http.ResponseWriter, r *http.Request) {
	u := userFromContext(r.Context())

	pols, err := a.cfg.Policies.List(r.Context(), u.TenantID)
	if err != nil {
		a.serverError(w, "reach: policies", err)
		return
	}

	inv, err := a.cfg.Devices.ListInventory(r.Context(), u.TenantID)
	if err != nil {
		a.serverError(w, "reach: devices", err)
		return
	}

	// Devices per policy, and the ones bound to nothing.
	//
	// Unbound devices are a group of their own rather than an omission:
	// they are the state that fails silently, so leaving them out of the
	// picture would hide exactly what the picture is for.
	byPolicy := map[string]int{}
	unbound := 0
	for i := range inv {
		if inv[i].Status != "active" {
			continue
		}
		if inv[i].PolicyID == nil {
			unbound++
			continue
		}
		byPolicy[inv[i].PolicyID.String()]++
	}

	type edge struct {
		Policy      string `json:"policy"`
		PolicyID    string `json:"policy_id"`
		CIDR        string `json:"cidr"`
		Description string `json:"description,omitempty"`
		DeviceCount int    `json:"device_count"`
	}

	var edges []edge
	cidrPolicies := map[string][]string{}

	for i := range pols {
		id := pols[i].ID.String()
		ips, err := a.cfg.Policies.ListAllowedIPs(r.Context(), pols[i].ID)
		if err != nil {
			a.serverError(w, "reach: allowed ips", err)
			return
		}
		for _, ip := range ips {
			edges = append(edges, edge{
				Policy:      pols[i].Name,
				PolicyID:    id,
				CIDR:        ip.CIDR,
				Description: ip.Description,
				DeviceCount: byPolicy[id],
			})
			cidrPolicies[ip.CIDR] = append(cidrPolicies[ip.CIDR], pols[i].Name)
		}

		// Virtual destinations are reach too. A phone under this policy
		// can get to the real address, by way of the virtual one — and
		// a reach map that left them out would show a server nobody can
		// reach when in fact a whole policy can. Drawn as
		// "virtual → real" so the rewrite is visible.
		vhs, err := a.cfg.Policies.ListVirtualHosts(r.Context(), pols[i].ID)
		if err != nil {
			a.serverError(w, "reach: virtual hosts", err)
			return
		}
		for _, vh := range vhs {
			label := vh.VirtualIP + " → " + vh.RealIP
			edges = append(edges, edge{
				Policy:      pols[i].Name,
				PolicyID:    id,
				CIDR:        label,
				Description: vh.Description,
				DeviceCount: byPolicy[id],
			})
			cidrPolicies[vh.RealIP+"/32"] = append(cidrPolicies[vh.RealIP+"/32"], pols[i].Name)
		}
	}

	// A CIDR opened by more than one policy.
	//
	// Exact-match only, deliberately. Real containment — 10.10.5.20/32
	// inside 10.10.0.0/16 — is the more useful check and needs prefix
	// arithmetic; this is the version that is certainly right, and
	// saying "these two policies open the same line" is already more
	// than the console could say before.
	overlaps := map[string][]string{}
	for cidr, names := range cidrPolicies {
		if len(names) > 1 {
			overlaps[cidr] = names
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"edges":    edges,
		"unbound":  unbound,
		"overlaps": overlaps,
	})
}
