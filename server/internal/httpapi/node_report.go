package httpapi

import (
	"encoding/json"
	"net/http"
	"time"
)

// The gateway tells the controller what it is actually doing.
//
// The agent has always polled for peers and never said anything back,
// so `nodes` held a seed row that read 활성 whether or not WireGuard was
// running. A handset connected, showed the key icon, reached nothing,
// and every screen agreed the node was fine.
//
// ## Why wg_backend is on the wire
//
// `wg-quick` falls back from the kernel module to wireguard-go without
// announcing it anywhere the operator will look. Both carry traffic and
// one is several times slower, so "why is this slow" currently ends in
// `docker compose logs`. It belongs on the dashboard.
func (a *API) registerNodeReportRoute(mux *http.ServeMux) {
	// requireNode, the same credential and middleware as GET /node/peers.
	//
	// requireAuth expects an OIDC token; the agent has a per-node token,
	// so it could never have authenticated here. And taking node_id from
	// the body let a caller report on behalf of any node — the
	// middleware already knows which node is calling, so the body should
	// not get to say.
	mux.Handle("POST /node/report", a.requireNode(http.HandlerFunc(a.nodeReport)))
}

func (a *API) nodeReport(w http.ResponseWriter, r *http.Request) {
	var body struct {
		WGBackend     string `json:"wg_backend"` // "kernel" | "userspace"
		WGInterfaceUp bool   `json:"wg_interface_up"`
		PeerCount     int    `json:"peer_count"`
		AgentVersion  string `json:"agent_version"`
		ResponderUp   bool   `json:"responder_up"`

		// Per-peer state from `wg show`.
		//
		// The handshake timestamp is the only evidence a device is
		// alive — WireGuard has no connected state, and status says
		// what an admin decided, not what the tunnel is doing.
		Peers []struct {
			PublicKey     string `json:"public_key"`
			LastHandshake int64  `json:"last_handshake"`
			Endpoint      string `json:"endpoint"` // unix seconds, 0 = never
			RxBytes       int64  `json:"rx_bytes"`
			TxBytes       int64  `json:"tx_bytes"`
			ViaRelay      bool   `json:"via_relay"`
		} `json:"peers"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	// From the credential, not the body.
	id := nodeFromContext(r.Context()).ID

	// Only the fields the agent owns. Status stays an admin decision —
	// a node an operator disabled must not re-enable itself by
	// reporting in.
	if err := a.cfg.Nodes.RecordReport(r.Context(), id,
		body.WGBackend, body.WGInterfaceUp, body.PeerCount, body.AgentVersion, body.ResponderUp); err != nil {
		a.serverError(w, "record node report", err)
		return
	}
	// Peer rows, keyed by public key — the only identifier the gateway
	// has. A key it does not recognise is skipped rather than erroring:
	// a peer removed mid-cycle is ordinary, not a fault.
	for _, p := range body.Peers {
		if p.LastHandshake == 0 {
			continue
		}
		_ = a.cfg.Devices.RecordHandshake(r.Context(),
			p.PublicKey, time.Unix(p.LastHandshake, 0).UTC(),
			p.RxBytes, p.TxBytes, p.ViaRelay, p.Endpoint)
	}

	// One fifteen-minute sample per report. Cheap, and it is the only
	// record of how many phones were connected an hour ago — the device
	// row holds a single last_handshake_at, which cannot answer that.
	a.sampleConnections(r, nodeFromContext(r.Context()).TenantID.Bytes())

	writeJSON(w, http.StatusOK, map[string]any{"at": time.Now().UTC().Format(time.RFC3339)})
}
