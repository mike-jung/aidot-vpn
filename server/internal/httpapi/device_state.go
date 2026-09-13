package httpapi

import (
	"errors"
	"github.com/aidotvpn/server/internal/devices"
	"net/http"
)

// Device-local policy view, authenticated independently of OIDC/mTLS so a
// revoked device can learn its status without receiving current policy data.
func (a *API) registerDeviceStateRoute(mux *http.ServeMux) {
	mux.Handle("GET /devices/{id}/state", a.requireDeviceStateAuth(http.HandlerFunc(a.deviceState)))
}

func (a *API) deviceState(w http.ResponseWriter, r *http.Request) {
	id, err := parseHexID(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid device id")
		return
	}

	dev, err := a.cfg.Devices.Get(r.Context(), id)
	if err != nil && !errors.Is(err, devices.ErrNotFound) {
		a.serverError(w, "device state: lookup", err)
		return
	}
	if errors.Is(err, devices.ErrNotFound) || dev == nil {
		// Unknown and deleted answer the same way. The app treats both
		// as "start over", which is the correct action for either.
		writeJSON(w, http.StatusOK, map[string]any{
			"status":       "revoked",
			"policy_bound": false,
		})
		return
	}

	if dev.Status != devices.StatusActive {
		writeJSON(w, http.StatusOK, map[string]any{"status": dev.Status, "policy_bound": false})
		return
	}

	allowedIPs, policyBound, err := a.effectivePolicy(r.Context(), id)
	if err != nil {
		a.serverError(w, "device state: effective policy", err)
		return
	}
	dns, allowedIPs, err := a.dnsFor(r.Context(), id, allowedIPs)
	if err != nil {
		a.serverError(w, "device state: DNS", err)
		return
	}

	scope, err := a.cfg.Policies.GetEffectiveRouteScope(r.Context(), id)
	if err != nil {
		a.serverError(w, "device state: route scope", err)
		return
	}

	// The gateway's current address, too.
	//
	// The app stored the node list at registration and never asked
	// again, so a gateway that moved — or a seed address corrected by
	// npm start — was invisible to every phone already enrolled. They
	// kept sending handshakes to 10.0.2.2, an address that exists only
	// inside the Android emulator, and logged twelve unanswered
	// attempts.
	//
	// A device that refreshes its policy on connect (1.6.6) should
	// refresh where to connect in the same call.
	peers, err := a.fetchPeerList(r.Context(), dev.TenantID)
	if err != nil {
		a.serverError(w, "device state: nodes", err)
		return
	}

	// Virtual → real, so the app can explain a failed probe against a
	// virtual address in terms of the real server. Without it the app
	// could only say "the server behind the gateway is down", which is
	// true but sends the user looking at the wrong address.
	vhosts, _ := a.cfg.Policies.VirtualHostsForDevice(r.Context(), id)
	vh := make([]map[string]string, 0, len(vhosts))
	for _, h := range vhosts {
		vh = append(vh, map[string]string{"virtual": h.VirtualIP, "real": h.RealIP})
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"status":              dev.Status,
		"policy_bound":        policyBound,
		"allowed_ips":         jsonList(allowedIPs),
		"route_scope":         string(scope),
		"dns_servers":         jsonList(dns.Servers),
		"dns_search_domains":  jsonList(dns.SearchDomains),
		"app_filter_mode":     string(dev.AppFilter.Mode),
		"app_filter_packages": jsonList(dev.AppFilter.Packages),
		"nodes":               peers,
		"virtual_hosts":       vh,
	})
}
