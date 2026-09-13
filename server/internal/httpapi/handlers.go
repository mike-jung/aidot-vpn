// Package httpapi exposes the AidotVpn admin REST API consumed by the
// Vue 3 admin console.
//
// Why REST and not Connect-RPC: the console is plain `fetch` (intentionally
// — see console/src/api/client.js) so it doesn't need protobuf at all.
// The Connect-RPC surface is reserved for the Android client and the
// data-node, which DO benefit from typed stubs and streaming RPCs.
//
// Endpoints exposed here (mounted at the same listener as /healthz):
//
//	GET  /devices                  → ListMyDevices for the calling user
//	POST /devices/{id}/revoke      → Revoke (admin or owner)
//	GET  /nodes                    → list nodes for the calling user's tenant
//	GET  /policies                 → static empty list (Phase 8)
//	GET  /audit                    → recent audit log entries
//	GET  /audit/verify             → verify hash chain
//
// Authentication: every handler is wrapped by RequireAuth which extracts
// a Keycloak-issued bearer token, verifies it via the OIDC verifier, and
// resolves (or upserts) a row in the `users` table keyed by the `sub`
// claim. The resolved User is attached to the request context so handlers
// can pull it out without re-verifying.
package httpapi

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/aidotvpn/server/internal/adminauth"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/aidotvpn/server/internal/allowlist"
	"github.com/aidotvpn/server/internal/audit"
	"github.com/aidotvpn/server/internal/devices"
	"github.com/aidotvpn/server/internal/domain"
	"github.com/aidotvpn/server/internal/nodes"
	"github.com/aidotvpn/server/internal/policies"
	"github.com/aidotvpn/server/internal/pqc"
	"github.com/aidotvpn/server/internal/users"
)

// Config groups all dependencies the API needs.
type Config struct {
	HAStatus func(context.Context) map[string]any
	Admins   *adminauth.Service
	Users    *users.Repo
	Devices  *devices.Service
	Nodes    *nodes.Service
	Audit    *audit.Writer
	Policies *policies.Service

	// KEM supplies tenant ML-KEM keypairs for hybrid post-quantum PSKs
	// (0.20.0). Optional: nil leaves every device on the classical PSK,
	// which is what happens when PQC_ENABLED is unset.
	KEM           *pqc.Store
	Allowlist     *allowlist.Service // optional — nil disables Phase 7 attestation challenges
	DefaultTenant domain.ID
	Logger        *slog.Logger
	// DB is used by registerDevice for the JOIN that hydrates a peer
	// list (node + node_endpoints) into the response. Required.
	DB *sql.DB
	// EnableDevAdmin opts the controller into a tiny unauthenticated
	// admin surface (`GET /admin/dev/peers`) used by the dev
	// wg-data-node sidecar to pull the current device list. NEVER
	// enable in production — there is no authn on that endpoint, and
	// it leaks all device public keys.
	EnableDevAdmin bool

	// RelaySigningKey is the HMAC key used to sign tokens that mobile
	// peers and data-nodes present to the cmd/relay process. Empty
	// disables the relay surface entirely (returns errors from the
	// /relay/* endpoints).
	RelaySigningKey string
	// RelaySharedSecret is the value the relay process sends in the
	// X-Relay-Secret header when calling /relay/verify-*. Different
	// from RelaySigningKey so a compromised relay can't forge tokens.
	RelaySharedSecret string
}

// API holds the resolved dependencies and exposes Register to mount its
// routes onto a ServeMux.
type API struct {
	cfg Config
}

// New constructs the API. All fields of cfg are required.
func New(cfg Config) (*API, error) {
	if cfg.Admins == nil {
		return nil, errors.New("httpapi.New: Admins required")
	}
	if cfg.Users == nil {
		return nil, errors.New("httpapi.New: Users required")
	}
	if cfg.Devices == nil {
		return nil, errors.New("httpapi.New: Devices required")
	}
	if cfg.Nodes == nil {
		return nil, errors.New("httpapi.New: Nodes required")
	}
	if cfg.Audit == nil {
		return nil, errors.New("httpapi.New: Audit required")
	}
	if cfg.Policies == nil {
		return nil, errors.New("httpapi.New: Policies required")
	}
	if cfg.DB == nil {
		return nil, errors.New("httpapi.New: DB required")
	}
	if cfg.DefaultTenant.IsZero() {
		return nil, errors.New("httpapi.New: DefaultTenant required")
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return &API{cfg: cfg}, nil
}

// Register mounts the API's routes on the given mux. Each handler is
// individually wrapped by RequireAuth.
func (a *API) Register(mux *http.ServeMux) {
	if a.cfg.HAStatus != nil {
		mux.Handle("GET /ha/status", a.requireAuth(a.requireAdmin(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Cache-Control", "no-store")
			_ = json.NewEncoder(w).Encode(a.cfg.HAStatus(r.Context()))
		}))))
	}
	// Note on routing: net/http (Go 1.22+) supports {id} path params and
	// method-specific patterns ("METHOD /path"). We use those instead of a
	// router framework to keep the dependency surface tiny.
	mux.Handle("GET /devices", a.requireAuth(http.HandlerFunc(a.listDevices)))
	mux.Handle("POST /devices/{id}/revoke", a.requireAuth(http.HandlerFunc(a.revokeDevice)))
	// Binding a device to a policy changes what that device can reach,
	// so it is an admin action — a user must not be able to widen their
	// own access by pointing their phone at a more permissive policy.
	mux.Handle("PUT /devices/{id}/policy", a.requireAuth(a.requireAdmin(http.HandlerFunc(a.assignDevicePolicy))))
	mux.Handle("PUT /devices/{id}/app-filter", a.requireAuth(http.HandlerFunc(a.updateDeviceAppFilter)))
	// Device-side registration flow. These routes are also under
	// requireAuth (Keycloak bearer token), because that's how a fresh
	// install proves it belongs to a real user. Once the device has its
	// mTLS cert, subsequent traffic flows through the gRPC plane on a
	// separate listener that uses cert SANs instead of bearer tokens.
	mux.Handle("POST /devices/register", a.requireAuthOrEnrollmentGrant(http.HandlerFunc(a.registerDevice)))
	mux.Handle("POST /devices/rotate-key", a.requireAuth(http.HandlerFunc(a.rotateDeviceKey)))
	// Same credential as /devices/register.
	//
	// RegistrationFlow fetches a challenge before registering, so a
	// device enrolling with a grant hits this first — and 1.2.8 left it
	// on requireAuth, which rejects a grant as a malformed JWT. The
	// approval succeeded and the phone still could not register.
	mux.Handle("POST /devices/attestation-challenge",
		a.requireAuthOrEnrollmentGrant(http.HandlerFunc(a.getAttestationChallenge)))
	mux.Handle("GET /nodes", a.requireAuth(http.HandlerFunc(a.listNodes)))
	mux.Handle("GET /policies", a.requireAuth(http.HandlerFunc(a.listPolicies)))
	mux.Handle("POST /policies", a.requireAuth(a.requireAdmin(http.HandlerFunc(a.createPolicy))))
	mux.Handle("GET /policies/{id}", a.requireAuth(http.HandlerFunc(a.getPolicy)))
	mux.Handle("PUT /policies/{id}", a.requireAuth(a.requireAdmin(http.HandlerFunc(a.updatePolicy))))
	mux.Handle("DELETE /policies/{id}", a.requireAuth(a.requireAdmin(http.HandlerFunc(a.deletePolicy))))
	mux.Handle("POST /policies/{id}/allowed-ips", a.requireAuth(a.requireAdmin(http.HandlerFunc(a.addAllowedIP))))
	mux.Handle("DELETE /policies/{id}/allowed-ips/{aipId}", a.requireAuth(a.requireAdmin(http.HandlerFunc(a.removeAllowedIP))))
	mux.Handle("GET /audit", a.requireAuth(http.HandlerFunc(a.listAudit)))
	mux.Handle("GET /audit/verify", a.requireAuth(http.HandlerFunc(a.verifyAudit)))

	// Relay support — see internal/relay. The relay process calls these
	// to verify tokens it receives from data-nodes / mobile peers. Auth
	// here is a shared secret (X-Relay-Secret), NOT user OIDC. Issuing
	// the token to the mobile side IS user-authenticated.
	mux.HandleFunc("POST /relay/verify-data-node", a.relayVerifyDataNode)
	mux.HandleFunc("POST /relay/verify-mobile", a.relayVerifyMobile)
	mux.Handle("POST /devices/{id}/relay-token",
		a.requireAuth(http.HandlerFunc(a.issueRelayToken)))

	// Enrollment tokens (1.1.1) — click-to-create device credentials.
	a.registerEnrollmentRoutes(mux)

	// Device-initiated enrollment with admin approval (1.2.0).
	a.registerEnrollmentRequestRoutes(mux)

	// The device asks whether it is still usable (1.5.3).
	a.registerDeviceStateRoute(mux)

	// The gateway reports what it is actually running (1.7.0).
	a.registerNodeReportRoute(mux)

	// The reach map — who can get where, through which policy (1.7.2).
	a.registerReachRoute(mux)

	// The port map, for 설정 (1.7.29).
	a.registerPortsRoute(mux)

	// Console login without an identity server (1.8.0).
	a.registerAdminAuthRoutes(mux)

	// 2단계 인증 (1.16.0).
	a.registerTOTPRoutes(mux)

	// 단말별 추적 (1.9.3).
	a.registerTraceRoutes(mux)

	// 개요 통계 (1.9.5).
	a.registerStatsRoutes(mux)

	// 그룹 — 정책을 여러 단말에 한 번에 (1.11.0).
	a.registerGroupRoutes(mux)

	// 접속 기한 (1.12.0).
	a.registerExpiryRoutes(mux)

	// How a policy's devices reach the gateway, and whether their source
	// address is rewritten (1.7.3).
	// Virtual destinations (1.7.22): the phone is told one address and
	// the gateway rewrites it to another.
	mux.Handle("GET /policies/{id}/virtual-hosts",
		a.requireAuth(a.requireAdmin(http.HandlerFunc(a.listVirtualHosts))))
	mux.Handle("POST /policies/{id}/virtual-hosts",
		a.requireAuth(a.requireAdmin(http.HandlerFunc(a.addVirtualHost))))
	mux.Handle("DELETE /policies/{id}/virtual-hosts/{hid}",
		a.requireAuth(a.requireAdmin(http.HandlerFunc(a.removeVirtualHost))))

	mux.Handle("PUT /policies/{id}/transport",
		a.requireAuth(a.requireAdmin(http.HandlerFunc(a.updatePolicyTransport))))

	// Read-only "what does this device actually have?" endpoint (0.26.0).
	a.registerDebugRoutes(mux)

	// Policy admin surface (0.16.0) — route scope, DNS push and hostname
	// rules. Configurable only via direct SQL before this.
	a.registerPolicyAdminRoutes(mux)

	// Gateway-facing API (0.10.0). Authenticated by per-node bearer
	// token; see nodeapi.go. This is what production gateways use.
	a.registerNodeRoutes(mux)

	// GET /admin/dev/peers was REMOVED in 0.14.0.
	//
	// It served an unauthenticated, tenancy-ignoring peer list and
	// included `pending_attest` devices, so unverified devices got
	// working WireGuard peers. `GET /node/peers` replaced it in 0.10.0
	// and removal was scheduled for 0.11.0 — it then slipped through
	// 0.12.0 and 0.13.0 while each release found something more urgent.
	// A deprecation that keeps slipping is just a permanent endpoint
	// with a warning attached, so it goes now.
	//
	// EnableDevAdmin is retained in Config for one release: a compose
	// file still setting AIDOTVPN_ENABLE_DEV_ADMIN should get a clear
	// log line rather than a silently ignored variable.
	if a.cfg.EnableDevAdmin {
		a.cfg.Logger.Warn("AIDOTVPN_ENABLE_DEV_ADMIN is set but /admin/dev/peers " +
			"was removed in 0.14.0 — the gateway must use GET /node/peers " +
			"with a token from `migrate node-token <hostname>`")
	}
}

// ----- handlers ------------------------------------------------------------

func (a *API) listDevices(w http.ResponseWriter, r *http.Request) {
	u := userFromContext(r.Context())

	// Admins see the tenant; everyone else sees their own handsets.
	//
	// Before this, an admin logging into the console got an empty list
	// while devices were registered — every device belonged to the
	// clinician who enrolled it, and the only query available was
	// "mine". Assigning a policy to a phone was therefore impossible
	// from the console, which is the first thing the tutorial asks a
	// reader to do.
	// Admins get the inventory view — assigned address, bound policy,
	// key expiry, owner. Those are the fields an admin needs to answer a
	// question about a device, and they are meaningless to a clinician
	// looking at their own handset.
	if IsAdmin(r.Context()) {
		inv, err := a.cfg.Devices.ListInventory(r.Context(), u.TenantID)
		if err != nil {
			a.serverError(w, "list device inventory", err)
			return
		}
		out := make([]map[string]any, 0, len(inv))
		for i := range inv {
			out = append(out, inventoryJSON(&inv[i]))
		}
		writeJSON(w, http.StatusOK, map[string]any{"devices": out})
		return
	}

	var devs []devices.Device
	var err error
	devs, err = a.cfg.Devices.ListMyDevices(r.Context(), u.ID)
	if err != nil {
		a.serverError(w, "list devices", err)
		return
	}
	out := make([]deviceJSON, 0, len(devs))
	for i := range devs {
		out = append(out, toDeviceJSON(&devs[i]))
	}
	writeJSON(w, http.StatusOK, map[string]any{"devices": out})
}

// inventoryJSON is the admin-facing device shape.
func inventoryJSON(d *devices.DeviceInventory) map[string]any {
	out := map[string]any{
		"id":           d.ID.String(),
		"display_name": d.DisplayName,
		"platform":     string(d.Platform),
		"status":       d.Status,
		"os_version":   d.OSVersion,
		"app_version":  d.AppVersion,
		"install_id":   d.InstallID,
		"owner_email":  d.OwnerEmail,
		"created_at":   d.CreatedAt.Format(time.RFC3339),

		// The join key between a firewall log and a person.
		"ipv4": d.IPv4,
		"ipv6": d.IPv6,

		// Named, not just bound: "which policy" is the question when a
		// device reaches more than it should.
		"policy_name": d.PolicyName,

		"app_filter_mode": string(d.AppFilter.Mode),
	}
	if d.PolicyID != nil {
		out["policy_id"] = d.PolicyID.String()
	}
	if d.LastSeenAt != nil {
		out["last_seen_at"] = d.LastSeenAt.Format(time.RFC3339)
	}
	// The handshake, not the API call.
	//
	// last_seen_at is when this device last talked to the controller —
	// true of a phone that registered and never connected. The
	// handshake is when it last talked to the gateway, which is the
	// only evidence the tunnel carries anything.
	if d.LastHandshakeAt != nil {
		out["last_handshake_at"] = d.LastHandshakeAt.Format(time.RFC3339)
	}
	if d.RxBytes != nil {
		out["rx_bytes"] = *d.RxBytes
	}
	if d.TxBytes != nil {
		out["tx_bytes"] = *d.TxBytes
	}
	if d.LastEndpoint != "" {
		out["last_endpoint"] = d.LastEndpoint
	}
	if d.PublicKey != "" {
		out["public_key"] = d.PublicKey
	}
	if d.Model != "" {
		out["model"] = d.Model
	}
	out["policy_direct"] = d.PolicyDirect
	if d.OSSdk > 0 {
		out["os_sdk"] = d.OSSdk
	}
	out["posture_blocked"] = d.PostureBlocked
	if d.AccessExpiresAt != nil {
		out["access_expires_at"] = d.AccessExpiresAt.UTC().Format(time.RFC3339)
		out["access_expired"] = d.AccessExpiresAt.Before(time.Now())
	}
	if d.GroupID != nil {
		out["group_id"] = d.GroupID.String()
		out["group_name"] = d.GroupName
	}
	if d.ViaRelay != nil {
		out["via_relay"] = *d.ViaRelay
	}
	if d.KeyActivatedAt != nil {
		out["key_activated_at"] = d.KeyActivatedAt.Format(time.RFC3339)
	}
	if d.KeyExpiresAt != nil {
		out["key_expires_at"] = d.KeyExpiresAt.Format(time.RFC3339)
	}
	return out
}

func (a *API) listVirtualHosts(w http.ResponseWriter, r *http.Request) {
	id, err := parseHexID(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid policy id")
		return
	}
	hs, err := a.cfg.Policies.ListVirtualHosts(r.Context(), id)
	if err != nil {
		a.serverError(w, "list virtual hosts", err)
		return
	}
	out := make([]map[string]any, 0, len(hs))
	for _, h := range hs {
		out = append(out, map[string]any{
			"id": h.ID.String(), "virtual_ip": h.VirtualIP,
			"real_ip": h.RealIP, "description": h.Description,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"virtual_hosts": out})
}

func (a *API) addVirtualHost(w http.ResponseWriter, r *http.Request) {
	id, err := parseHexID(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid policy id")
		return
	}
	var body struct {
		VirtualIP   string `json:"virtual_ip"`
		RealIP      string `json:"real_ip"`
		Description string `json:"description"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	// The controller's own machine cannot be a virtual destination.
	//
	// On Docker Desktop the gateway container cannot reach the host by
	// its LAN address at all — the WSL2 network has no route back to
	// its own host, and a probe from inside the container to
	// 192.168.0.11:10030 timed out flat. A rewrite to that address is
	// a packet into a void. The controller is already reachable inside
	// the tunnel at 10.78.0.1:10030, which is what to use.
	if isLocalAddress(body.RealIP + "/32") {
		writeError(w, http.StatusBadRequest,
			"진짜 주소가 관리실(컨트롤러) 자신입니다. 도커 문지기는 자기 호스트의 LAN 주소로 "+
				"갈 수 없습니다. 컨트롤러는 터널 안 10.78.0.1:10030 으로 이미 닿습니다 — 가상 주소가 "+
				"필요 없습니다. 시험용이라면 진짜 주소에 10.78.0.1 (문지기 자신) 을 적으세요.")
		return
	}

	u := userFromContext(r.Context())
	h, err := a.cfg.Policies.AddVirtualHost(r.Context(), id, u.ID,
		body.VirtualIP, body.RealIP, body.Description)
	if err != nil {
		if errors.Is(err, policies.ErrNotFound) {
			writeError(w, http.StatusNotFound, "정책을 찾을 수 없습니다")
			return
		}
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"id": h.ID.String(), "virtual_ip": h.VirtualIP, "real_ip": h.RealIP,
	})
}

func (a *API) removeVirtualHost(w http.ResponseWriter, r *http.Request) {
	id, err := parseHexID(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid policy id")
		return
	}
	hid, err := parseHexID(r.PathValue("hid"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid host id")
		return
	}
	u := userFromContext(r.Context())
	if err := a.cfg.Policies.RemoveVirtualHost(r.Context(), id, hid, u.ID); err != nil {
		a.serverError(w, "remove virtual host", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) updatePolicyTransport(w http.ResponseWriter, r *http.Request) {
	id, err := parseHexID(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid policy id")
		return
	}
	var body struct {
		EndpointMode   string `json:"endpoint_mode"`
		SourceNAT      bool   `json:"source_nat"`
		ControlChannel string `json:"control_channel"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	u := userFromContext(r.Context())
	// Default rather than reject an omitted value: the field arrived in
	// 1.7.12 and a console that has not reloaded would otherwise fail
	// every save with a message about a field the operator cannot see.
	channel := body.ControlChannel
	if channel == "" {
		channel = "direct"
	}
	if err := a.cfg.Policies.UpdateTransport(r.Context(), id, u.ID,
		body.EndpointMode, body.SourceNAT, channel); err != nil {
		if errors.Is(err, policies.ErrNotFound) {
			writeError(w, http.StatusNotFound, "정책을 찾을 수 없습니다")
			return
		}
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) revokeDevice(w http.ResponseWriter, r *http.Request) {
	u := userFromContext(r.Context())
	idStr := r.PathValue("id")
	deviceID, err := parseHexID(idStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid device id")
		return
	}
	var body struct {
		Reason string `json:"reason"`
	}
	if r.Body != nil {
		_ = json.NewDecoder(r.Body).Decode(&body) // empty body is fine
	}
	if err := a.cfg.Devices.Revoke(r.Context(), deviceID, u.ID, body.Reason); err != nil {
		a.serverError(w, "revoke device", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// updateDeviceAppFilter writes the per-app split tunnel rule for one
// device. The caller (the user's bearer-token session) must own the
// device. We do a cheap ownership check by comparing the device's
// user_id to the session user_id; tenant admins gain blanket access
// only via their realm role, which is a Phase 9 enhancement.
//
// Body shape:
//
//	{ "mode": "off" | "include" | "exclude",
//	  "packages": ["com.example.app", "com.acme.intranet"] }
//
// 200 on success returns the updated deviceJSON so the console can
// refresh its local row without re-listing.
func (a *API) updateDeviceAppFilter(w http.ResponseWriter, r *http.Request) {
	u := userFromContext(r.Context())
	idStr := r.PathValue("id")
	deviceID, err := parseHexID(idStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid device id")
		return
	}

	var body struct {
		Mode     string   `json:"mode"`
		Packages []string `json:"packages"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	// Use the same tenant-scoped admin / device-owner gate as policy
	// assignment. Approved enrollment devices belong to their enrollment
	// user, so listing only the administrator's own devices rejects them.
	owned, err := a.ownsDevice(r, deviceID)
	if err != nil {
		a.serverError(w, "device ownership check", err)
		return
	}
	if !owned {
		writeError(w, http.StatusNotFound, "device not found")
		return
	}

	if err := a.cfg.Devices.UpdateAppFilter(r.Context(), deviceID, u.ID,
		devices.AppFilterMode(body.Mode), body.Packages); err != nil {
		writeError(w, http.StatusBadRequest, "update app filter: "+err.Error())
		return
	}

	// Return the updated row so the UI can refresh in place.
	updated, err := a.cfg.Devices.Get(r.Context(), deviceID)
	if err != nil {
		a.serverError(w, "read updated device", err)
		return
	}
	writeJSON(w, http.StatusOK, toDeviceJSON(updated))
}

func (a *API) listNodes(w http.ResponseWriter, r *http.Request) {
	u := userFromContext(r.Context())
	ns, err := a.cfg.Nodes.ListByTenant(r.Context(), u.TenantID)
	if err != nil {
		a.serverError(w, "list nodes", err)
		return
	}
	// What the admin actually asks about the gateway — is it up, where
	// do phones connect, how many are on it right now — alongside the
	// stored row. The endpoint list and the live device count are
	// tenant-wide today (one gateway); per-node when there are several.
	endpoints, _ := a.fetchPeerList(r.Context(), u.TenantID)
	// SUM(CASE …) rather than COUNT(*) FILTER: the FILTER clause is
	// PostgreSQL, and MariaDB rejected it — which this code discarded
	// with `_ =` and reported 0/0 for a tenant with a device on it.
	var online, total int
	if err := a.cfg.DB.QueryRowContext(r.Context(), `
		SELECT COALESCE(SUM(CASE WHEN last_handshake_at > NOW(6) - INTERVAL 2 MINUTE THEN 1 ELSE 0 END), 0),
		       COUNT(*)
		  FROM devices WHERE tenant_id = ? AND deleted_at IS NULL AND status = 'active'`,
		u.TenantID.Bytes()).Scan(&online, &total); err != nil {
		a.cfg.Logger.Warn("list nodes: device counts", "err", err)
	}

	out := make([]map[string]any, 0, len(ns))
	for i := range ns {
		j := toNodeJSON(&ns[i])
		row := map[string]any{
			"id": j.ID, "hostname": j.Hostname, "status": j.Status,
			"last_seen_at": j.LastSeenAt, "last_report_at": j.LastReportAt,
			"wg_backend": j.WGBackend, "wg_interface_up": j.WGInterfaceUp,
			"peer_count": j.PeerCount, "agent_version": j.AgentVersion,
			"responder_up":   j.ResponderUp,
			"online_devices": online, "total_devices": total,
			"tunnel_address": "10.78.0.1",
		}
		if len(endpoints) > 0 {
			row["public_endpoints"] = endpoints[0]["endpoints"]
			row["public_key"] = endpoints[0]["public_key"]
		}
		out = append(out, row)
	}
	writeJSON(w, http.StatusOK, map[string]any{"nodes": out})
}

// ----- device registration (Phase 5/6/7 unified flow) ---------------------

// registerDevice handles the first-time enrollment of an Android (or other
// platform) client. The caller is the user's bearer-token-authenticated
// session. The flow:
//
//  1. Decode the JSON body into the format the SDK sends.
//  2. Decode the base64'd device public key + the PEM CSR.
//  3. Call devices.Service.Register, which generates the user's IPv4/v6
//     allocation, signs the CSR into an mTLS cert, and persists state.
//  4. List the tenant's nodes so the client knows where to connect.
//  5. Return the device + allocation + node list as JSON.
func (a *API) registerDevice(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	u := userFromContext(r.Context())

	var body struct {
		InstallID           string `json:"install_id"`
		DisplayName         string `json:"display_name"`
		Platform            string `json:"platform"`
		OSVersion           string `json:"os_version"`
		AppVersion          string `json:"app_version"`
		Model               string `json:"model"`
		OSSdk               int    `json:"os_sdk"`
		DevicePublicKey     string `json:"device_public_key"` // base64
		AttestationToken    string `json:"attestation_token"`
		ClientCertCSRPEM    string `json:"client_cert_csr_pem"`   // PEM
		AttestationChainPEM string `json:"attestation_chain_pem"` // PEM bundle
		// 0.17.0: which Android shell is registering. Empty defaults to
		// standalone, which every pre-0.17.0 client is.
		DeploymentMode string `json:"deployment_mode"`
		HostPackage    string `json:"host_package"`
		// 0.20.0: base64 ML-KEM-768 ciphertext for a hybrid PQ PSK.
		// Optional — absent means the classical PSK.
		KEMCiphertext string `json:"kem_ciphertext"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	pubKey, err := base64.StdEncoding.DecodeString(body.DevicePublicKey)
	if err != nil {
		writeError(w, http.StatusBadRequest, "device_public_key is not valid base64")
		return
	}
	if len(pubKey) != 32 {
		writeError(w, http.StatusBadRequest, "device_public_key must decode to 32 bytes")
		return
	}

	platform := devices.Platform(body.Platform)
	if platform == "" {
		platform = devices.PlatformOther
	}

	// Decode the optional KEM ciphertext before touching the service, so
	// a malformed value is a 400 rather than a mid-transaction failure.
	var kemCT []byte
	if body.KEMCiphertext != "" {
		kemCT, err = base64.StdEncoding.DecodeString(body.KEMCiphertext)
		if err != nil {
			writeError(w, http.StatusBadRequest, "kem_ciphertext is not valid base64")
			return
		}
	}

	res, err := a.cfg.Devices.Register(r.Context(), devices.RegisterParams{
		TenantID:         u.TenantID,
		UserID:           u.ID,
		InstallID:        body.InstallID,
		DisplayName:      body.DisplayName,
		Platform:         platform,
		OSVersion:        body.OSVersion,
		AppVersion:       body.AppVersion,
		Model:            body.Model,
		OSSdk:            body.OSSdk,
		DevicePublicKey:  pubKey,
		AttestationToken: body.AttestationToken,
		// 0.13.0: the chain is finally forwarded. It was decoded from the
		// request body and then dropped on the floor here, which is why
		// hardware attestation never actually ran.
		AttestationChainPEM: []byte(body.AttestationChainPEM),
		DeploymentMode:      devices.DeploymentMode(body.DeploymentMode),
		HostPackage:         body.HostPackage,
		KEMCiphertext:       kemCT,
		ClientCertCSRPEM:    []byte(body.ClientCertCSRPEM),
	})
	if err != nil {
		// Attestation refusal is a policy decision, not a client
		// mistake — 403 so the SDK can show "this device is not
		// permitted" rather than "bad request".
		if errors.Is(err, devices.ErrAttestationFailed) {
			writeError(w, http.StatusForbidden, err.Error())
			return
		}
		// Database constraint violations must not reach the client
		// (0.22.0). End-to-end testing surfaced a registration failing
		// with the raw text:
		//
		//   register failed: insertDeviceKey: Error 1062 (23000):
		//   Duplicate entry '\xE5\xB6...' for key 'uq_device_keys_pubkey'
		//
		// That leaks the schema — table, column, index name and a
		// fragment of another device's key material — to whoever
		// triggered it, and tells the caller nothing they can act on.
		// The operator still gets the full error in the log below.
		if isConstraintViolation(err) {
			a.cfg.Logger.Warn("register hit a database constraint",
				"err", err.Error(), "user", u.ID.String())
			// Name the constraint that actually fired.
			//
			// Every violation used to be reported as a duplicate key,
			// which sent an operator chasing a fresh keypair for what was
			// a (user_id, install_id) collision — advice that could not
			// work, on a cause that was not the cause.
			msg := "등록할 수 없습니다. 잠시 후 다시 시도하세요."
			switch {
			case strings.Contains(err.Error(), "uq_device_keys_pubkey"):
				msg = "이 기기 키는 이미 등록되어 있습니다. 앱을 다시 실행해 새 키로 시도하세요."
			case strings.Contains(err.Error(), "uq_devices_user_install"):
				msg = "이 설치본은 이미 등록되어 있습니다. 앱 데이터를 지우고 다시 등록하세요."
			}
			writeError(w, http.StatusConflict, msg)
			return
		}
		// Validation errors (bad fields) → 400. Anything else → 500.
		// devices.Service returns descriptive errors so we surface the
		// whole message; the API caller is the device's own SDK, not a
		// general public.
		a.cfg.Logger.Info("register failed", "err", err.Error(), "user", u.ID.String())
		writeError(w, http.StatusBadRequest, "register failed: "+err.Error())
		return
	}

	// Pull peer list (node + node_endpoints) for the client. Without
	// this hydration the SDK gets an empty `nodes` array and refuses
	// to bring the tunnel up ("no node available").
	peers, err := a.fetchPeerList(r.Context(), u.TenantID)
	if err != nil {
		a.serverError(w, "fetch peer list after register", err)
		return
	}

	// A device enrolled by approval gets the policy the admin chose.
	//
	// Bound here rather than in the approval handler: the device did not
	// exist then. Before the allocation is computed below, so the response
	// already carries the policy's allowed IPs — otherwise the phone shows
	// an empty list until something else refreshes it.
	if pid, ok := enrollmentPolicyFrom(r.Context()); ok {
		if err := a.cfg.Policies.AssignToDevice(r.Context(), res.Device.ID, pid, u.ID); err != nil {
			a.serverError(w, "bind policy after enrollment", err)
			return
		}
	}

	allowedIPs, policyBound, err := a.effectivePolicy(r.Context(), res.Device.ID)
	if err != nil {
		a.serverError(w, "effective policy after register", err)
		return
	}
	routeScope, err := a.routeScopeFor(r.Context(), res.Device.ID)
	if err != nil {
		a.serverError(w, "route scope after register", err)
		return
	}
	dns, allowedIPs, err := a.dnsFor(r.Context(), res.Device.ID, allowedIPs)
	if err != nil {
		a.serverError(w, "dns settings after register", err)
		return
	}
	kemAlg, kemKey := a.kemMaterial(r.Context(), u.TenantID)

	writeJSON(w, http.StatusOK, map[string]any{
		"device": toDeviceJSON(&res.Device),
		"allocation": allocationJSON(&res.Allocation, allowedIPs, policyBound, routeScope, dns, kemAlg, kemKey,
			a.controlChannelURLFor(r.Context(), res.Device.ID)),
		"nodes": peers,
	})
}

// effectivePolicy resolves the destination CIDRs a device is allowed to
// reach, plus whether an admin has bound it to a policy at all.
//
// The two are distinct: a device bound to a policy that happens to have
// zero CIDRs is "bound but reaches nothing" (an admin mid-edit), while
// an unbound device is "not yet provisioned". Both deny traffic, but the
// client shows a different message for each.
func (a *API) effectivePolicy(ctx context.Context, deviceID domain.ID) ([]string, bool, error) {
	cidrs, err := a.cfg.Policies.GetEffectiveAllowedIPs(ctx, deviceID)
	if err != nil {
		return nil, false, err
	}
	bound, err := a.cfg.Policies.IsDeviceBound(ctx, deviceID)
	if err != nil {
		return nil, false, err
	}
	return cidrs, bound, nil
}

// dnsFor returns the device's DNS settings, with each resolver address
// folded into the allowed CIDR list.
//
// The fold is not a convenience. Android sends DNS queries for the VPN
// network to the pushed servers; if the tunnel has no route to one, every
// lookup times out and the user sees a connected VPN on which nothing
// works. Making the route implicit removes a step an admin would
// otherwise have to remember on every policy.
func (a *API) dnsFor(
	ctx context.Context,
	deviceID domain.ID,
	allowedIPs []string,
) (policies.DNSSettings, []string, error) {
	dns, err := a.cfg.Policies.GetEffectiveDNS(ctx, deviceID)
	if err != nil {
		return policies.DNSSettings{}, allowedIPs, err
	}
	for _, srv := range dns.Servers {
		addr, perr := netip.ParseAddr(strings.TrimSpace(srv))
		if perr != nil {
			a.cfg.Logger.Warn("policy has an unparseable DNS server; skipping",
				"value", srv, "device", deviceID.String())
			continue
		}
		bits := 32
		if addr.Is6() {
			bits = 128
		}
		host := fmt.Sprintf("%s/%d", addr.String(), bits)
		if !containsString(allowedIPs, host) {
			allowedIPs = append(allowedIPs, host)
		}
	}
	return dns, allowedIPs, nil
}

func containsString(hay []string, needle string) bool {
	for _, h := range hay {
		if h == needle {
			return true
		}
	}
	return false
}

// kemMaterial returns the tenant's encapsulation key for the allocation
// response, or empty strings when PQC is not configured.
//
// Best-effort: a failure here must not break registration. The hybrid PSK
// is an enhancement on top of a classical PSK that is already secure
// today, so refusing to enrol a clinician because a key lookup hiccupped
// would trade a real outage for a hypothetical future one.
func (a *API) kemMaterial(ctx context.Context, tenantID domain.ID) (algorithm, encapB64 string) {
	if a.cfg.KEM == nil {
		return "", ""
	}
	encap, err := a.cfg.KEM.EnsureKeypair(ctx, tenantID)
	if err != nil {
		a.cfg.Logger.Warn("could not obtain tenant KEM key; "+
			"clients will keep using the classical PSK",
			"tenant", tenantID.String(), "err", err.Error())
		return "", ""
	}
	return pqc.AlgorithmMLKEM768, base64.StdEncoding.EncodeToString(encap)
}

// routeScopeFor returns the device's route scope as a wire string.
func (a *API) routeScopeFor(ctx context.Context, deviceID domain.ID) (string, error) {
	sc, err := a.cfg.Policies.GetEffectiveRouteScope(ctx, deviceID)
	if err != nil {
		return string(policies.RouteScopePolicy), err
	}
	return string(sc), nil
}

// rotateDeviceKey is the periodic key-rotation endpoint. Identifies the
// device by the same bearer token (we don't run mTLS on the REST plane;
// the gRPC plane is where mTLS lives). The user must already own a
// device with the install_id implied here — we look it up by user.
func (a *API) rotateDeviceKey(w http.ResponseWriter, r *http.Request) {
	u := userFromContext(r.Context())

	var body struct {
		NewDevicePublicKey string `json:"new_device_public_key"`
		AttestationToken   string `json:"attestation_token"`
		ClientCertCSRPEM   string `json:"client_cert_csr_pem"`
		// Carried on rotation too — omitting it would quietly downgrade
		// a PQ-protected device to the classical PSK at its next cycle.
		KEMCiphertext string `json:"kem_ciphertext"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	pubKey, err := base64.StdEncoding.DecodeString(body.NewDevicePublicKey)
	if err != nil {
		writeError(w, http.StatusBadRequest, "new_device_public_key is not valid base64")
		return
	}
	if len(pubKey) != 32 {
		writeError(w, http.StatusBadRequest, "new_device_public_key must decode to 32 bytes")
		return
	}

	// Find the user's most recently active device. In a future iteration
	// we'll let the client pass install_id explicitly to disambiguate
	// when one user has multiple devices.
	devs, err := a.cfg.Devices.ListMyDevices(r.Context(), u.ID)
	if err != nil {
		a.serverError(w, "list devices for rotate", err)
		return
	}
	if len(devs) == 0 {
		writeError(w, http.StatusNotFound, "no device to rotate; register first")
		return
	}
	target := &devs[0]

	var rotateKemCT []byte
	if body.KEMCiphertext != "" {
		rotateKemCT, err = base64.StdEncoding.DecodeString(body.KEMCiphertext)
		if err != nil {
			writeError(w, http.StatusBadRequest, "kem_ciphertext is not valid base64")
			return
		}
	}

	res, err := a.cfg.Devices.RotateKey(r.Context(), devices.RotateKeyParams{
		DeviceID:           target.ID,
		NewDevicePublicKey: pubKey,
		AttestationToken:   body.AttestationToken,
		ClientCertCSRPEM:   []byte(body.ClientCertCSRPEM),
		KEMCiphertext:      rotateKemCT,
	})
	if err != nil {
		a.cfg.Logger.Info("rotate failed", "err", err.Error(), "device", target.ID.String())
		writeError(w, http.StatusBadRequest, "rotate failed: "+err.Error())
		return
	}
	allowedIPs, policyBound, err := a.effectivePolicy(r.Context(), target.ID)
	if err != nil {
		a.serverError(w, "effective policy after rotate", err)
		return
	}
	routeScope, err := a.routeScopeFor(r.Context(), target.ID)
	if err != nil {
		a.serverError(w, "route scope after rotate", err)
		return
	}
	dns, allowedIPs, err := a.dnsFor(r.Context(), target.ID, allowedIPs)
	if err != nil {
		a.serverError(w, "dns settings after rotate", err)
		return
	}
	kemAlg, kemKey := a.kemMaterial(r.Context(), u.TenantID)
	writeJSON(w, http.StatusOK, map[string]any{
		"allocation": allocationJSON(&res.Allocation, allowedIPs, policyBound, routeScope, dns, kemAlg, kemKey,
			a.controlChannelURLFor(r.Context(), target.ID)),
	})
}

// getAttestationChallenge issues a server-side nonce that the device must
// bake into its KeyGenParameterSpec.setAttestationChallenge() call. The
// resulting attestation chain proves the device generated the keypair
// in TEE/StrongBox at this server's request — preventing replay of an
// old chain from a compromised device.
//
// If the Phase-7 allowlist service isn't wired in yet, returns 501 so
// the SDK can gracefully degrade (registration still works without
// attestation, the device just lands in the pending_attest state).
func (a *API) getAttestationChallenge(w http.ResponseWriter, r *http.Request) {
	if a.cfg.Allowlist == nil {
		writeError(w, http.StatusNotImplemented, "attestation not enabled")
		return
	}
	u := userFromContext(r.Context())
	chal, err := a.cfg.Allowlist.IssueChallenge(r.Context(), u.TenantID, u.ID)
	if err != nil {
		a.serverError(w, "issue attestation challenge", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"challenge_hex": hex.EncodeToString(chal),
	})
}

// listPolicies returns the tenant's policies (without AllowedIPs hydrated;
// the detail view fetches those separately).
func (a *API) listPolicies(w http.ResponseWriter, r *http.Request) {
	u := userFromContext(r.Context())
	pols, err := a.cfg.Policies.List(r.Context(), u.TenantID)
	if err != nil {
		a.serverError(w, "list policies", err)
		return
	}
	out := make([]policyJSON, 0, len(pols))
	for i := range pols {
		out = append(out, toPolicyJSON(&pols[i]))
	}
	writeJSON(w, http.StatusOK, map[string]any{"policies": out})
}

func (a *API) getPolicy(w http.ResponseWriter, r *http.Request) {
	u := userFromContext(r.Context())
	id, err := parseHexID(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid policy id")
		return
	}
	p, err := a.cfg.Policies.GetWithAllowedIPs(r.Context(), id)
	if err != nil {
		if errors.Is(err, policies.ErrNotFound) {
			writeError(w, http.StatusNotFound, "policy not found")
			return
		}
		a.serverError(w, "get policy", err)
		return
	}
	if p.TenantID != u.TenantID {
		// Tenant isolation: don't leak existence of policies in other tenants.
		writeError(w, http.StatusNotFound, "policy not found")
		return
	}
	writeJSON(w, http.StatusOK, toPolicyJSON(p))
}

func (a *API) createPolicy(w http.ResponseWriter, r *http.Request) {
	u := userFromContext(r.Context())
	var body struct {
		Name        string `json:"name"`
		Description string `json:"description"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	p, err := a.cfg.Policies.Create(r.Context(), u.TenantID, u.ID, body.Name, body.Description)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, toPolicyJSON(p))
}

func (a *API) updatePolicy(w http.ResponseWriter, r *http.Request) {
	u := userFromContext(r.Context())
	id, err := parseHexID(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid policy id")
		return
	}
	// Tenant guard: confirm the policy belongs to caller before mutating.
	existing, err := a.cfg.Policies.Get(r.Context(), id)
	if err != nil {
		if errors.Is(err, policies.ErrNotFound) {
			writeError(w, http.StatusNotFound, "policy not found")
			return
		}
		a.serverError(w, "get policy", err)
		return
	}
	if existing.TenantID != u.TenantID {
		writeError(w, http.StatusNotFound, "policy not found")
		return
	}
	var body struct {
		Name        string `json:"name"`
		Description string `json:"description"`
		Enabled     bool   `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if err := a.cfg.Policies.Update(r.Context(), id, u.ID, body.Name, body.Description, body.Enabled); err != nil {
		a.serverError(w, "update policy", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) deletePolicy(w http.ResponseWriter, r *http.Request) {
	u := userFromContext(r.Context())
	id, err := parseHexID(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid policy id")
		return
	}
	existing, err := a.cfg.Policies.Get(r.Context(), id)
	if err != nil {
		if errors.Is(err, policies.ErrNotFound) {
			writeError(w, http.StatusNotFound, "policy not found")
			return
		}
		a.serverError(w, "get policy", err)
		return
	}
	if existing.TenantID != u.TenantID {
		writeError(w, http.StatusNotFound, "policy not found")
		return
	}
	if err := a.cfg.Policies.Delete(r.Context(), id, u.ID); err != nil {
		a.serverError(w, "delete policy", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) addAllowedIP(w http.ResponseWriter, r *http.Request) {
	u := userFromContext(r.Context())
	policyID, err := parseHexID(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid policy id")
		return
	}
	existing, err := a.cfg.Policies.Get(r.Context(), policyID)
	if err != nil {
		if errors.Is(err, policies.ErrNotFound) {
			writeError(w, http.StatusNotFound, "policy not found")
			return
		}
		a.serverError(w, "get policy", err)
		return
	}
	if existing.TenantID != u.TenantID {
		writeError(w, http.StatusNotFound, "policy not found")
		return
	}
	var body struct {
		CIDR        string `json:"cidr"`
		Description string `json:"description"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	// Refuse the controller's own address, rather than warn after saving.
	//
	// 1.7.23 warned. The row still landed, still listed, still went to
	// every phone under the policy — where TunnelManager silently drops
	// it (1.6.9). A line the admin can see and the phone will never
	// honour is worse than a refusal: it looks like configuration.
	if isLocalAddress(body.CIDR) {
		writeError(w, http.StatusBadRequest,
			"이 주소는 관리실(컨트롤러) 자신입니다. 폰은 관리실 주소를 터널에서 일부러 "+
				"제외하므로 이 줄은 적용될 수 없습니다. 문지기 뒤의 서버 주소를 적으세요.")
		return
	}

	row, err := a.cfg.Policies.AddAllowedIP(r.Context(), policyID, u.ID, body.CIDR, body.Description)
	if err != nil {
		// Surface CIDR validation errors as 400 instead of 500.
		if errors.Is(err, policies.ErrInvalidCIDR) {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		a.serverError(w, "add allowed-ip", err)
		return
	}
	out := map[string]any{
		"id": row.ID.String(), "cidr": row.CIDR, "description": row.Description,
	}
	// Warn when the line names this machine.
	//
	// The phone excludes the controller's address from its tunnel on
	// purpose (1.6.9) — the channel that says "why is the tunnel down"
	// cannot live inside the tunnel. So a policy line for the
	// controller's own address is accepted, stored, listed, and silently
	// never applied. An admin added 172.30.1.16/32 expecting it to route
	// and had no way to learn it would not.
	writeJSON(w, http.StatusCreated, out)
}

// isLocalAddress reports whether a /32 names one of this host's own
// interface addresses. The controller runs where npm start runs, so
// "this host" is the controller.
func isLocalAddress(cidr string) bool {
	host := cidr
	if i := strings.Index(cidr, "/"); i >= 0 {
		if cidr[i+1:] != "32" && cidr[i+1:] != "128" {
			return false // a range, not one host
		}
		host = cidr[:i]
	}
	target, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return false
	}
	for _, a := range addrs {
		if ipn, ok := a.(*net.IPNet); ok {
			if ip, ok := netip.AddrFromSlice(ipn.IP); ok && ip.Unmap() == target.Unmap() {
				return true
			}
		}
	}
	return false
}

func (a *API) removeAllowedIP(w http.ResponseWriter, r *http.Request) {
	u := userFromContext(r.Context())
	policyID, err := parseHexID(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid policy id")
		return
	}
	allowedIPID, err := parseHexID(r.PathValue("aipId"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid allowed-ip id")
		return
	}
	// Tenant guard via the parent policy.
	existing, err := a.cfg.Policies.Get(r.Context(), policyID)
	if err != nil {
		if errors.Is(err, policies.ErrNotFound) {
			writeError(w, http.StatusNotFound, "policy not found")
			return
		}
		a.serverError(w, "get policy", err)
		return
	}
	if existing.TenantID != u.TenantID {
		writeError(w, http.StatusNotFound, "policy not found")
		return
	}
	if err := a.cfg.Policies.RemoveAllowedIP(r.Context(), allowedIPID, u.ID); err != nil {
		if errors.Is(err, policies.ErrNotFound) {
			writeError(w, http.StatusNotFound, "allowed-ip not found")
			return
		}
		a.serverError(w, "remove allowed-ip", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// assignDevicePolicy points a device at a policy (or unassigns when
// policy_id is empty/null in the body).
func (a *API) assignDevicePolicy(w http.ResponseWriter, r *http.Request) {
	u := userFromContext(r.Context())
	deviceID, err := parseHexID(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid device id")
		return
	}
	// Device ownership gate (0.11.0).
	//
	// This check was missing: the handler validated that the POLICY
	// belonged to the caller's tenant and then applied it to whatever
	// device ID appeared in the URL — including devices belonging to
	// another tenant entirely. updateDeviceAppFilter, twenty lines
	// below, had the gate all along; the two disagreed.
	owns, err := a.ownsDevice(r, deviceID)
	if err != nil {
		a.serverError(w, "device ownership check", err)
		return
	}
	if !owns {
		// 404 rather than 403: confirming that an ID exists but belongs
		// to someone else is itself a disclosure.
		writeError(w, http.StatusNotFound, "device not found")
		return
	}

	var body struct {
		PolicyID string `json:"policy_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	var policyID domain.ID
	if body.PolicyID != "" {
		policyID, err = parseHexID(body.PolicyID)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid policy id")
			return
		}
		// Tenant guard.
		existing, err := a.cfg.Policies.Get(r.Context(), policyID)
		if err != nil {
			if errors.Is(err, policies.ErrNotFound) {
				writeError(w, http.StatusNotFound, "policy not found")
				return
			}
			a.serverError(w, "get policy", err)
			return
		}
		if existing.TenantID != u.TenantID {
			writeError(w, http.StatusNotFound, "policy not found")
			return
		}
	}
	if err := a.cfg.Policies.AssignToDevice(r.Context(), deviceID, policyID, u.ID); err != nil {
		if errors.Is(err, policies.ErrNotFound) {
			writeError(w, http.StatusNotFound, "device or policy not found")
			return
		}
		a.serverError(w, "assign policy", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) listAudit(w http.ResponseWriter, r *http.Request) {
	u := userFromContext(r.Context())
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	if limit <= 0 {
		limit = 100
	}
	cursor, _ := strconv.ParseUint(q.Get("cursor"), 10, 64)
	// from/to as YYYY-MM-DD (the console's date inputs) or RFC3339.
	// "to" is inclusive of the whole day when given as a date, which is
	// what someone typing two dates means.
	parseWhen := func(v string, endOfDay bool) time.Time {
		if v == "" {
			return time.Time{}
		}
		if t, err := time.Parse("2006-01-02", v); err == nil {
			if endOfDay {
				return t.AddDate(0, 0, 1)
			}
			return t
		}
		t, _ := time.Parse(time.RFC3339, v)
		return t
	}
	from := parseWhen(q.Get("from"), false)
	to := parseWhen(q.Get("to"), true)

	entries, err := a.cfg.Audit.ListByTenant(r.Context(), u.TenantID, limit, cursor, from, to)
	if err != nil {
		a.serverError(w, "list audit", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"entries": entries})
}

// verifyAudit walks the entire chain for the user's tenant and returns
// the verification status. For tenants with millions of entries this
// would need bounded ranges; for AidotVpn dev/early prod the chain is
// small enough to verify wholesale.
func (a *API) verifyAudit(w http.ResponseWriter, r *http.Request) {
	bad, err := a.cfg.Audit.Verify(r.Context(), 0, 0)
	if err != nil {
		a.serverError(w, "verify audit", err)
		return
	}
	if bad != nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"valid":   false,
			"bad_seq": bad.ID.String(),
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"valid": true})
}

// ----- JSON projections ----------------------------------------------------

// We deliberately project a stable JSON shape (not the internal Go type)
// so the console doesn't depend on internal type changes. The shapes
// match what console/src/views/*.vue templates expect.

type deviceJSON struct {
	ID                string     `json:"id"`
	UserID            string     `json:"user_id"`
	InstallID         string     `json:"install_id"`
	DisplayName       string     `json:"display_name"`
	Platform          string     `json:"platform"`
	OSVersion         string     `json:"os_version,omitempty"`
	AppVersion        string     `json:"app_version,omitempty"`
	Model             string     `json:"model,omitempty"`
	Status            string     `json:"status"`
	LastSeenAt        *time.Time `json:"last_seen_at,omitempty"`
	CreatedAt         time.Time  `json:"created_at"`
	AppFilterMode     string     `json:"app_filter_mode"`
	AppFilterPackages []string   `json:"app_filter_packages"`
	// DeploymentMode / HostPackage (migration 0010, exposed in 0.17.0).
	// Lets the console show which shell owns the tunnel and spot the
	// same handset registered twice.
	DeploymentMode string `json:"deployment_mode"`
	HostPackage    string `json:"host_package,omitempty"`
}

func toDeviceJSON(d *devices.Device) deviceJSON {
	mode := string(d.AppFilter.Mode)
	if mode == "" {
		mode = string(devices.AppFilterOff)
	}
	pkgs := d.AppFilter.Packages
	if pkgs == nil {
		pkgs = []string{}
	}
	return deviceJSON{
		ID:                d.ID.String(),
		UserID:            d.UserID.String(),
		InstallID:         d.InstallID,
		DisplayName:       d.DisplayName,
		Platform:          string(d.Platform),
		OSVersion:         d.OSVersion,
		AppVersion:        d.AppVersion,
		Status:            string(d.Status),
		LastSeenAt:        d.LastSeenAt,
		CreatedAt:         d.CreatedAt,
		AppFilterMode:     mode,
		AppFilterPackages: pkgs,
		DeploymentMode:    deploymentModeOrDefault(d.DeploymentMode),
		HostPackage:       d.HostPackage,
	}
}

// isConstraintViolation reports whether err is a MySQL/MariaDB integrity
// error whose text must not be echoed to a client.
//
// Matched on the driver's error string rather than a typed check: the
// project depends on go-sql-driver only for its driver registration, and
// importing its error type here to switch on Number would spread that
// dependency into the HTTP layer for one comparison.
func isConstraintViolation(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	for _, code := range []string{
		"Error 1062", // duplicate entry
		"Error 1452", // foreign key: cannot add or update child row
		"Error 1451", // foreign key: cannot delete parent row
		"Error 1048", // column cannot be null
	} {
		if strings.Contains(msg, code) {
			return true
		}
	}
	return false
}

// deploymentModeOrDefault keeps the wire value non-empty. A device row
// predating migration 0010 carries the column default anyway; this guards
// the in-memory zero value so the console never has to render "".
func deploymentModeOrDefault(m devices.DeploymentMode) string {
	if !m.Valid() {
		return string(devices.DeploymentStandalone)
	}
	return string(m)
}

type nodeJSON struct {
	ID            string     `json:"id"`
	Hostname      string     `json:"hostname"`
	Region        string     `json:"region"`
	Status        string     `json:"status"`
	LastSeenAt    *time.Time `json:"last_seen_at,omitempty"`
	LastReportAt  *time.Time `json:"last_report_at,omitempty"`
	WGBackend     string     `json:"wg_backend,omitempty"`
	WGInterfaceUp *bool      `json:"wg_interface_up,omitempty"`
	PeerCount     *int       `json:"peer_count,omitempty"`
	AgentVersion  string     `json:"agent_version,omitempty"`
	ResponderUp   *bool      `json:"responder_up,omitempty"`
}

func toNodeJSON(n *nodes.Node) nodeJSON {
	return nodeJSON{
		ID:         n.ID.String(),
		Hostname:   n.Hostname,
		Region:     n.Region,
		Status:     n.Status,
		LastSeenAt: n.LastSeenAt,

		// What the gateway said about itself, as opposed to what the
		// row says. status reads 활성 on a seed node with nothing
		// running behind it; these are empty until an agent reports,
		// which is the distinction the console needs to draw.
		LastReportAt:  n.LastReportAt,
		WGBackend:     n.WGBackend,
		WGInterfaceUp: n.WGInterfaceUp,
		PeerCount:     n.PeerCount,
		AgentVersion:  n.AgentVersion,
		ResponderUp:   n.ResponderUp,
	}
}

type policyJSON struct {
	ID           string          `json:"id"`
	Name         string          `json:"name"`
	Description  string          `json:"description,omitempty"`
	Enabled      bool            `json:"enabled"`
	Precedence   int             `json:"precedence"`
	CreatedAt    time.Time       `json:"created_at"`
	UpdatedAt    time.Time       `json:"updated_at"`
	AllowedIPs   []allowedIPJSON `json:"allowed_ips,omitempty"`
	SourceNAT    bool            `json:"source_nat"`
	EndpointMode string          `json:"endpoint_mode"`
	// Where this policy's devices reach the controller: the compiled-in
	// address, or the tunnel.
	ControlChannel string `json:"control_channel"`
}

func toPolicyJSON(p *policies.Policy) policyJSON {
	out := policyJSON{
		ID:          p.ID.String(),
		Name:        p.Name,
		Description: p.Description,
		Enabled:     p.Enabled,
		Precedence:  p.Precedence,
		CreatedAt:   p.CreatedAt,
		UpdatedAt:   p.UpdatedAt,

		// How this policy's devices reach the gateway, and whether
		// their source address is rewritten on the way.
		SourceNAT:      p.SourceNAT,
		EndpointMode:   p.EndpointMode,
		ControlChannel: p.ControlChannel,
	}
	if p.AllowedIPs != nil {
		out.AllowedIPs = make([]allowedIPJSON, 0, len(p.AllowedIPs))
		for i := range p.AllowedIPs {
			out.AllowedIPs = append(out.AllowedIPs, toAllowedIPJSON(&p.AllowedIPs[i]))
		}
	}
	return out
}

type allowedIPJSON struct {
	ID          string `json:"id"`
	CIDR        string `json:"cidr"`
	Description string `json:"description,omitempty"`
}

func toAllowedIPJSON(a *policies.AllowedIP) allowedIPJSON {
	return allowedIPJSON{
		ID:          a.ID.String(),
		CIDR:        a.CIDR,
		Description: a.Description,
	}
}

// ----- dev-only admin handlers --------------------------------------------

// ----- registration response shape ----------------------------------------

// allocationJSON projects devices.Allocation into the format the Android
// SDK's AllocationModel expects.
//
// We base64-encode the binary fields (device public key, PSK) because
// AndroidSDK.KeyUtils handles base64 round-trip; sending raw bytes
// inside JSON would require client-side hex decoding we don't have.
// jsonList returns a slice that marshals as [] rather than null.
//
// Go serialises a nil slice as `null`. Kotlin's model declares these as
// `List<String> = emptyList()`, and kotlinx-serialization rejects an
// explicit null for a non-nullable property regardless of the default:
//
//	Unexpected JSON token at offset 1689: Expected start of the array
//	'[', but had 'n' instead at path: $.allocation.dns_search_domains
//
// Fixing the client alone would leave the API sending null for an array,
// which the next consumer has to discover the same way. An empty list is
// what "no DNS servers" means; null is an accident of the language.
func jsonList(v []string) []string {
	if v == nil {
		return []string{}
	}
	return v
}

// tunnelControllerURL is where the controller answers inside the tunnel.
//
// The gateway holds the tunnel's first address and proxies this port to
// the real controller, so the value is the same for every tenant and
// does not need to be stored per device.
//
// Overridable because a deployment may put the gateway on a different
// tunnel address; the default matches infra/wireguard/wg0.conf.
// controlChannelURLFor returns the tunnel address when this device's
// policy asks for it, and "" when it does not.
//
// "" means the app keeps using the address it was built with — which is
// what an app from before this field did anyway.
func (a *API) controlChannelURLFor(ctx context.Context, deviceID domain.ID) string {
	pol, err := a.cfg.Policies.ForDevice(ctx, deviceID)
	if err != nil || pol == nil || pol.ControlChannel != "tunnel" {
		return ""
	}
	return tunnelControllerURL()
}

func tunnelControllerURL() string {
	if v := os.Getenv("CONTROLLER_TUNNEL_URL"); v != "" {
		return v
	}
	return "http://10.78.0.1:10030"
}

func allocationJSON(
	a *devices.Allocation,
	allowedIPs []string,
	policyBound bool,
	routeScope string,
	dns policies.DNSSettings,
	kemAlgorithm string,
	kemEncapKey string,
	controlChannelURL string,
) map[string]any {
	mode := string(a.AppFilter.Mode)
	if mode == "" {
		mode = string(devices.AppFilterOff)
	}
	pkgs := a.AppFilter.Packages
	if pkgs == nil {
		pkgs = []string{}
	}
	if allowedIPs == nil {
		allowedIPs = []string{}
	}
	out := map[string]any{
		"device_public_key":      base64.StdEncoding.EncodeToString(a.DeviceKey.PublicKey),
		"psk":                    base64.StdEncoding.EncodeToString(a.PSK.PSK),
		"psk_source":             string(a.PSK.Source),
		"state_token":            a.StateToken,
		"client_cert_pem":        string(a.ClientCertPEM),
		"ca_cert_pem":            string(a.CACertPEM),
		"client_cert_expires_at": a.ClientCertExpiresAt.UTC().Format(time.RFC3339),
		// AllowedIPs (0.10.0). These are the CIDRs the device's assigned
		// policy permits, resolved by policies.GetEffectiveAllowedIPs.
		//
		// IMPORTANT: this list is a *routing* hint for the client, not a
		// security boundary. The authoritative destination ACL is applied
		// by the gateway agent's nftables ruleset (see cmd/gateway-agent).
		// A tampered client can ignore this list; it cannot get past the
		// gateway.
		"allowed_ips": jsonList(allowedIPs),
		// policy_bound tells the client whether an admin has actually
		// assigned a policy. Pre-0.10.0 clients ignore the field and keep
		// their old "empty list = full tunnel" fallback; 0.10.0+ clients
		// refuse to connect when this is false (deny-by-default).
		"policy_bound": policyBound,
		// route_scope (0.12.0) — what happens to traffic the policy does
		// not permit.
		//
		//   "policy" : split tunnel. Only the CIDRs above are routed;
		//              everything else uses the normal network.
		//   "full"   : lockdown. 0.0.0.0/0 + ::/0 are routed, and the
		//              gateway drops whatever the policy doesn't allow —
		//              so the tunnelled apps reach the permitted servers
		//              and nothing else at all.
		//
		// Older clients ignore the field and behave as "policy", which is
		// the pre-0.12.0 behaviour.
		"route_scope": routeScope,
		// DNS push (0.15.0). Empty means "leave system DNS alone", which
		// is the pre-0.15.0 behaviour and what older clients do anyway.
		//
		// The resolver's own address is automatically added to
		// allowed_ips above — a pushed DNS server that the tunnel does
		// not route to produces a device where nothing resolves at all,
		// which looks like a total outage rather than a config mistake.
		"dns_servers":        jsonList(dns.Servers),
		"dns_search_domains": jsonList(dns.SearchDomains),
		// Where to reach the controller once the tunnel is up.
		//
		// The client compiles in a bootstrap address because
		// registration happens before a tunnel exists. Everything after
		// that can go over the tunnel, to an address that means nothing
		// outside it — so an unpacked APK stops carrying the hospital's
		// internal host.
		//
		// The gateway proxies this to the real controller; see
		// infra/wireguard/reachability-target.py.
		// Only when the policy asks for it.
		//
		// Sending it unconditionally would let the app decide, and the
		// decision belongs to the admin: the tunnel route depends on the
		// gateway proxy running, and a device that cannot reach the
		// controller cannot be told it was revoked.
		//
		// Absent means "keep using the address you were built with",
		// which is what an older app does anyway.
		"controller_tunnel_url": controlChannelURL,

		// The tenant's ML-KEM-768 encapsulation key (0.20.0). Public by
		// construction. A client that can do ML-KEM encapsulates against
		// it and sends the ciphertext on its NEXT register or rotate,
		// which is when the hybrid PSK takes effect — the current
		// allocation's PSK is already issued.
		//
		// Empty when the controller has no PQC store configured.
		"kem_algorithm": kemAlgorithm,
		"kem_encap_key": kemEncapKey,
		// Per-app split tunnel (Phase 8). The Android client uses these
		// as a snapshot at the time of register/rotate-key. Live
		// updates after this snapshot require either a fresh
		// rotateKey (12h cycle) or — Phase 9 — a server push channel.
		"app_filter_mode":     mode,
		"app_filter_packages": jsonList(pkgs),
	}
	if a.DeviceKey.IPv4.IsValid() {
		out["ipv4_addr"] = a.DeviceKey.IPv4.String()
	}
	if a.DeviceKey.IPv6.IsValid() {
		out["ipv6_addr"] = a.DeviceKey.IPv6.String()
	}
	return out
}

// fetchPeerList returns the full WG peer description (node id, region,
// pubkey base64, list of endpoints) for every active node visible to
// the tenant. The SDK's NodeModel mirrors this shape — keep the JSON
// keys aligned with `client-android/core/.../Models.kt`.
//
// We do this inline rather than adding a method to internal/nodes
// because the JSON projection is tightly coupled to the SDK's wire
// format; pushing it down to the service layer would force two places
// to evolve in lockstep when the proto changes.
func (a *API) fetchPeerList(ctx context.Context, tenantID domain.ID) ([]map[string]any, error) {
	rows, err := a.cfg.DB.QueryContext(ctx, `
		SELECT n.id, n.region, n.public_key
		  FROM nodes n
		 WHERE n.tenant_id = ?
		   AND n.deleted_at IS NULL
		   AND n.status IN ('active', 'draining')
		 ORDER BY n.hostname ASC`,
		tenantID.Bytes())
	if err != nil {
		return nil, fmt.Errorf("fetch nodes: %w", err)
	}
	defer rows.Close()

	type rawNode struct {
		id     domain.ID
		region string
		pubkey []byte
	}
	var raws []rawNode
	for rows.Next() {
		var (
			n       rawNode
			idBytes []byte
		)
		if err := rows.Scan(&idBytes, &n.region, &n.pubkey); err != nil {
			return nil, err
		}
		if err := n.id.Scan(idBytes); err != nil {
			return nil, err
		}
		raws = append(raws, n)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	out := make([]map[string]any, 0, len(raws))
	for _, n := range raws {
		// Endpoints per node — small N, so the per-node query is cheap
		// and clearer than a single multi-row JOIN in this context.
		eps, err := a.fetchNodeEndpoints(ctx, n.id)
		if err != nil {
			return nil, err
		}
		out = append(out, map[string]any{
			"id":         n.id.String(),
			"region":     n.region,
			"public_key": base64.StdEncoding.EncodeToString(n.pubkey),
			"endpoints":  eps,
		})
	}
	return out, nil
}

func (a *API) fetchNodeEndpoints(ctx context.Context, nodeID domain.ID) ([]map[string]any, error) {
	rows, err := a.cfg.DB.QueryContext(ctx, `
		SELECT id, mode, public_host, public_port
		  FROM node_endpoints
		 WHERE node_id = ? AND enabled = TRUE`,
		nodeID.Bytes())
	if err != nil {
		return nil, fmt.Errorf("fetch endpoints: %w", err)
	}
	defer rows.Close()
	var out []map[string]any
	for rows.Next() {
		var (
			idBytes []byte
			mode    string
			host    string
			port    uint16
		)
		if err := rows.Scan(&idBytes, &mode, &host, &port); err != nil {
			return nil, err
		}
		var id domain.ID
		if err := id.Scan(idBytes); err != nil {
			return nil, err
		}
		out = append(out, map[string]any{
			"id":          id.String(),
			"mode":        mode,
			"public_host": host,
			"public_port": int(port),
		})
	}
	return out, rows.Err()
}

// ----- helpers -------------------------------------------------------------

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func (a *API) serverError(w http.ResponseWriter, op string, err error) {
	a.cfg.Logger.Error(op, "err", err.Error())
	writeError(w, http.StatusInternalServerError, op+" failed")
}

func parseHexID(s string) (domain.ID, error) {
	// We accept either dashed UUID form (e.g. "01956000-...") or plain
	// hex (32 chars). domain.ID.UnmarshalText handles dashes.
	var id domain.ID
	if err := id.UnmarshalText([]byte(s)); err == nil {
		return id, nil
	}
	// Strip dashes and try as plain hex.
	clean := strings.ReplaceAll(s, "-", "")
	b, err := hex.DecodeString(clean)
	if err != nil {
		return id, fmt.Errorf("not hex: %w", err)
	}
	if err := id.Scan(b); err != nil {
		return id, err
	}
	return id, nil
}

// ----- context wiring ------------------------------------------------------

type ctxKey struct{}

func userFromContext(ctx context.Context) *users.User {
	u, _ := ctx.Value(ctxKey{}).(*users.User)
	return u
}

func contextWithUser(ctx context.Context, u *users.User) context.Context {
	return context.WithValue(ctx, ctxKey{}, u)
}

// ----- relay-auth handlers -----------------------------------------------
//
// The relay process (cmd/relay) calls these to verify the tokens it
// receives over WebSocket from data-nodes and mobile peers. The relay
// itself is never a privileged actor — it's a dumb forwarder — so the
// trust path is: relay asks controller "is this token valid?" with a
// shared secret in `X-Relay-Secret`, controller answers from its
// database.
//
// Token shape (deliberately simple to keep the relay stateless):
//
//   - Data-node tokens: HMAC(secret, "node:" + node_id + ":" + nonce)
//   - Mobile tokens:    HMAC(secret, "mob:"  + device_id + ":" + nonce)
//
// Both are issued by the controller, signed with `RELAY_SIGNING_KEY`,
// time-bound (24h for nodes, 5min for mobile per request).
//
// We deliberately pass the token as a form field rather than JSON so
// access logs at any reverse proxy don't capture it in URLs.

const relayTokenPrefixNode = "node:"
const relayTokenPrefixMobile = "mob:"

// relayVerifyDataNode checks the X-Relay-Secret then verifies a data-node
// token. Returns the canonical node_id on success.
func (a *API) relayVerifyDataNode(w http.ResponseWriter, r *http.Request) {
	if !a.checkRelaySecret(r) {
		writeError(w, http.StatusUnauthorized, "bad relay secret")
		return
	}
	tok := r.PostFormValue("token")
	if tok == "" {
		_ = r.ParseForm()
		tok = r.FormValue("token")
	}
	if tok == "" {
		writeError(w, http.StatusBadRequest, "missing token")
		return
	}
	id, err := a.verifyRelayToken(tok, relayTokenPrefixNode)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"node_id": id})
}

func (a *API) relayVerifyMobile(w http.ResponseWriter, r *http.Request) {
	if !a.checkRelaySecret(r) {
		writeError(w, http.StatusUnauthorized, "bad relay secret")
		return
	}
	tok := r.PostFormValue("token")
	if tok == "" {
		_ = r.ParseForm()
		tok = r.FormValue("token")
	}
	if tok == "" {
		writeError(w, http.StatusBadRequest, "missing token")
		return
	}
	id, err := a.verifyRelayToken(tok, relayTokenPrefixMobile)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"session_id": id})
}

// issueRelayToken mints a 5-minute token the mobile client uses to
// connect to the relay. The user must own the device (URL :id matches
// one of their devices).
func (a *API) issueRelayToken(w http.ResponseWriter, r *http.Request) {
	u := userFromContext(r.Context())
	deviceID, err := parseHexID(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid device id")
		return
	}
	devs, err := a.cfg.Devices.ListMyDevices(r.Context(), u.ID)
	if err != nil {
		a.serverError(w, "list devices for relay-token", err)
		return
	}
	owns := false
	for i := range devs {
		if devs[i].ID == deviceID {
			owns = true
			break
		}
	}
	if !owns {
		writeError(w, http.StatusNotFound, "device not found")
		return
	}
	tok, err := a.signRelayToken(relayTokenPrefixMobile + deviceID.String())
	if err != nil {
		a.serverError(w, "sign relay token", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"token":      tok,
		"expires_in": 300, // seconds
	})
}

func (a *API) checkRelaySecret(r *http.Request) bool {
	got := r.Header.Get("X-Relay-Secret")
	want := a.cfg.RelaySharedSecret
	// Constant-time compare. Empty want disables the relay surface.
	if want == "" {
		return false
	}
	if len(got) != len(want) {
		return false
	}
	var diff byte
	for i := 0; i < len(got); i++ {
		diff |= got[i] ^ want[i]
	}
	return diff == 0
}

// signRelayToken builds "v1.<unix-exp>.<payload>.<hmac>" using
// HMAC-SHA256 over `RELAY_SIGNING_KEY`. Token is base64url-friendly.
func (a *API) signRelayToken(payload string) (string, error) {
	if a.cfg.RelaySigningKey == "" {
		return "", errors.New("relay signing key not configured")
	}
	exp := time.Now().Add(5 * time.Minute).Unix()
	if strings.HasPrefix(payload, relayTokenPrefixNode) {
		exp = time.Now().Add(24 * time.Hour).Unix()
	}
	body := fmt.Sprintf("v1.%d.%s", exp, payload)
	mac := hmacSHA256([]byte(a.cfg.RelaySigningKey), []byte(body))
	return body + "." + base64.RawURLEncoding.EncodeToString(mac), nil
}

func (a *API) verifyRelayToken(tok, expectedPrefix string) (string, error) {
	if a.cfg.RelaySigningKey == "" {
		return "", errors.New("relay disabled")
	}
	parts := strings.Split(tok, ".")
	if len(parts) != 4 || parts[0] != "v1" {
		return "", errors.New("malformed token")
	}
	exp, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		return "", errors.New("bad exp")
	}
	if time.Now().Unix() > exp {
		return "", errors.New("token expired")
	}
	payload := parts[2]
	if !strings.HasPrefix(payload, expectedPrefix) {
		return "", errors.New("token role mismatch")
	}
	body := strings.Join(parts[:3], ".")
	expected := hmacSHA256([]byte(a.cfg.RelaySigningKey), []byte(body))
	got, err := base64.RawURLEncoding.DecodeString(parts[3])
	if err != nil {
		return "", errors.New("bad signature encoding")
	}
	if !hmacEqual(expected, got) {
		return "", errors.New("signature mismatch")
	}
	return strings.TrimPrefix(payload, expectedPrefix), nil
}

func hmacSHA256(key, body []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(body)
	return mac.Sum(nil)
}

func hmacEqual(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}
