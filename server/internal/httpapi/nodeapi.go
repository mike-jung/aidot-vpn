package httpapi

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/aidotvpn/server/internal/domain"
	"github.com/aidotvpn/server/internal/policies"
)

// This file implements the gateway-facing API added in 0.10.0.
//
// Before 0.10.0 the gateway's peer sync ran against `GET /admin/dev/peers`,
// which had no authentication at all and was gated behind a dev-only flag.
// Production deployments were therefore stuck: enable it and expose an
// unauthenticated peer list, or disable it and lose peer sync.
//
// `GET /node/peers` replaces it. It is authenticated with a per-node
// bearer token (SHA-256 hash stored in `nodes.agent_token_hash`) and,
// crucially, it returns *more* than the old endpoint: alongside each
// peer's public key and tunnel address it carries the destination ACL
// that the gateway must enforce in nftables.
//
// That extra payload is the difference between "the client promises to
// only talk to 10.10.5.20" and "the gateway drops everything else".

// registerNodeRoutes mounts the gateway-facing routes.
func (a *API) registerNodeRoutes(mux *http.ServeMux) {
	mux.Handle("GET /node/peers", a.requireNode(http.HandlerFunc(a.nodePeers)))
	mux.Handle("POST /node/relay-token", a.requireNode(http.HandlerFunc(a.nodeRelayToken)))
}

// nodeCtxKey carries the authenticated node through the request context.
type nodeCtxKey struct{}

type authedNode struct {
	ID       domain.ID
	TenantID domain.ID
	Hostname string
}

func nodeFromContext(ctx context.Context) authedNode {
	n, _ := ctx.Value(nodeCtxKey{}).(authedNode)
	return n
}

// requireNode authenticates a gateway agent by its bearer token.
//
// We hash the presented token and look it up rather than iterating rows
// and comparing in Go: the index does the work, and there is no
// timing-comparison surface on the hot path. The one constant-time
// compare below guards the (already narrow) case where two nodes were
// mistakenly provisioned with the same token.
func (a *API) requireNode(inner http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw := bearerFrom(r)
		if raw == "" {
			writeError(w, http.StatusUnauthorized, "missing node token")
			return
		}
		sum := sha256.Sum256([]byte(raw))

		rows, err := a.cfg.DB.QueryContext(r.Context(), `
			SELECT id, tenant_id, hostname, agent_token_hash
			  FROM nodes
			 WHERE agent_token_hash = ?
			   AND deleted_at IS NULL
			   AND status IN ('active', 'draining', 'provisioning')`,
			sum[:])
		if err != nil {
			a.serverError(w, "node auth lookup", err)
			return
		}
		defer rows.Close()

		var matches []authedNode
		for rows.Next() {
			var (
				idB, tenB, hashB []byte
				hostname         string
			)
			if err := rows.Scan(&idB, &tenB, &hostname, &hashB); err != nil {
				a.serverError(w, "node auth scan", err)
				return
			}
			if subtle.ConstantTimeCompare(hashB, sum[:]) != 1 {
				continue
			}
			var n authedNode
			if err := n.ID.Scan(idB); err != nil {
				continue
			}
			if err := n.TenantID.Scan(tenB); err != nil {
				continue
			}
			n.Hostname = hostname
			matches = append(matches, n)
		}
		if err := rows.Err(); err != nil {
			a.serverError(w, "node auth iterate", err)
			return
		}

		switch len(matches) {
		case 0:
			a.cfg.Logger.Info("node auth rejected",
				"token_fp", hex.EncodeToString(sum[:4]), "remote", r.RemoteAddr)
			writeError(w, http.StatusUnauthorized, "invalid node token")
			return
		case 1:
			// Happy path.
		default:
			// Two nodes share a token. Refusing is the only safe answer:
			// serving one of them at random would hand node A's peer
			// list (and therefore node B's tenant's device keys) to
			// whichever row sorted first.
			a.cfg.Logger.Error("node token collision — refusing",
				"count", len(matches), "token_fp", hex.EncodeToString(sum[:4]))
			writeError(w, http.StatusConflict,
				"node token is ambiguous; re-issue tokens for the affected nodes")
			return
		}

		node := matches[0]
		if _, err := a.cfg.DB.ExecContext(r.Context(),
			`UPDATE nodes SET agent_synced_at = CURRENT_TIMESTAMP(6) WHERE id = ?`,
			node.ID.Bytes()); err != nil {
			// Non-fatal: a failed timestamp update must not break peer
			// sync. The gateway going stale is a much worse outcome than
			// a missing "last synced" value in the console.
			a.cfg.Logger.Warn("node agent_synced_at update failed", "err", err.Error())
		}

		ctx := context.WithValue(r.Context(), nodeCtxKey{}, node)
		inner.ServeHTTP(w, r.WithContext(ctx))
	})
}

// nodePeerJSON is one entry of the gateway's desired state.
type nodePeerJSON struct {
	DeviceID  string `json:"device_id"`
	PublicKey string `json:"public_key"` // base64, WG Curve25519
	IPv4      string `json:"ipv4,omitempty"`
	IPv6      string `json:"ipv6,omitempty"`
	Status    string `json:"status"`

	// The pre-shared key, base64, or "" when the device has none.
	//
	// Registration mints a PSK and hands it to the phone, and the phone
	// mixes it into its handshake. The gateway never received it, so it
	// built its handshake response without one — and the phone, mixing
	// in a key the gateway did not, could not open the reply. The log
	// read "Received invalid response message from 192.168.0.11:52840",
	// twenty-two times, one per attempt. Both sides now hold the same
	// key; the response opens.
	PSK string `json:"psk,omitempty"`

	// PolicyBound mirrors the client-side flag. A peer that is not bound
	// to a policy gets its WG peer installed (so it can complete a
	// handshake and receive a clear "not provisioned" signal) but zero
	// nftables accepts, so it reaches nothing.
	PolicyBound bool `json:"policy_bound"`

	// DestCIDRs is the coarse destination ACL. Rendered as
	// `ip daddr <cidr> accept` per entry.
	DestCIDRs []string `json:"dest_cidrs"`

	// Rules refine DestCIDRs with protocol/port. When present, the
	// gateway emits these INSTEAD of the bare CIDR accepts for the
	// prefixes they cover.
	Rules []nodeRuleJSON `json:"rules,omitempty"`

	// Destinations the gateway rewrites. The phone sends to Virtual;
	// the forward ACL is written against Real, because DNAT runs first.
	Rewrites []nodeRewriteJSON `json:"rewrites,omitempty"`

	// From policies with source_nat set — this device's traffic to
	// these is masqueraded. Existed since 1.6.0 and was never put on
	// the wire, so the gateway never saw it.
	NATCIDRs []string `json:"nat_cidrs,omitempty"`
}

type nodeRewriteJSON struct {
	Virtual string `json:"virtual"`
	Real    string `json:"real"`
}

type nodeRuleJSON struct {
	Action   string `json:"action"`
	Dst      string `json:"dst"`
	Protocol string `json:"protocol"`
	PortMin  uint16 `json:"port_min,omitempty"`
	PortMax  uint16 `json:"port_max,omitempty"`
}

// nodePeers returns the authoritative peer list plus each peer's
// destination ACL.
//
// Scope: peers are limited to the authenticated node's tenant. The old
// dev endpoint ignored tenancy entirely and returned every device in the
// database — harmless in a single-tenant dev box, a cross-customer data
// leak the moment a second tenant exists.
//
// Device status: unlike the dev endpoint, `pending_attest` devices are
// NOT included. That endpoint's `status IN ('active','pending_attest')`
// meant an unverified device got a working WG peer on the gateway. Here
// only `active` devices are peers.
func (a *API) nodePeers(w http.ResponseWriter, r *http.Request) {
	node := nodeFromContext(r.Context())

	rows, err := a.cfg.DB.QueryContext(r.Context(), `
		SELECT d.id, d.status, dk.public_key, dk.ipv4_addr, dk.ipv6_addr,
		       (SELECT ps.psk FROM device_psks ps
		         WHERE ps.device_key_id = dk.id AND ps.revoked_at IS NULL
		         ORDER BY ps.activated_at DESC LIMIT 1) AS psk
		  FROM devices d
		  JOIN device_keys dk ON dk.device_id = d.id AND dk.revoked_at IS NULL
		  JOIN tenants t ON t.id = d.tenant_id
		 WHERE d.tenant_id = ?
		   AND d.deleted_at IS NULL
		   AND d.status = 'active'
		   -- Expired access is not handed to the gateway.
		   --
		   -- Enforced here rather than by a sweep that revokes rows: the
		   -- peer list is rebuilt on every report, so a device drops off
		   -- the moment its deadline passes and comes back if an admin
		   -- extends it, with no job to run and nothing to get stuck
		   -- half-done. The device row stays 'active' and the console
		   -- shows 만료됨, because expiry is not revocation — the phone
		   -- did nothing wrong and re-approval should be one click.
		   AND (d.access_expires_at IS NULL OR d.access_expires_at > NOW(6))
		   -- Posture: an OS too old to be patched does not get a tunnel.
		   --
		   -- Only when the tenant set a minimum and the device reported
		   -- a number. A device that never reported one is not silently
		   -- excluded — the check would then punish an old client
		   -- version rather than an old phone, which is not what an
		   -- admin asked for.
		   AND (t.min_os_sdk = 0 OR d.os_sdk IS NULL OR d.os_sdk >= t.min_os_sdk)
		 ORDER BY d.id`,
		node.TenantID.Bytes())
	if err != nil {
		a.serverError(w, "node peers query", err)
		return
	}
	defer rows.Close()

	type rawPeer struct {
		id      domain.ID
		status  string
		pubKey  []byte
		ipv4Raw []byte
		ipv6Raw []byte
		psk     []byte
	}
	var raws []rawPeer
	for rows.Next() {
		var (
			p   rawPeer
			idB []byte
		)
		if err := rows.Scan(&idB, &p.status, &p.pubKey, &p.ipv4Raw, &p.ipv6Raw, &p.psk); err != nil {
			a.serverError(w, "node peers scan", err)
			return
		}
		if err := p.id.Scan(idB); err != nil {
			continue
		}
		raws = append(raws, p)
	}
	if err := rows.Err(); err != nil {
		a.serverError(w, "node peers iterate", err)
		return
	}

	peers := make([]nodePeerJSON, 0, len(raws))
	for _, p := range raws {
		cidrs, bound, err := a.effectivePolicy(r.Context(), p.id)
		if err != nil {
			a.serverError(w, "node peers policy", err)
			return
		}
		// Fold pushed DNS resolvers into the gateway's accept list too
		// (0.15.0).
		//
		// The client and the gateway must agree on this or the tunnel is
		// silently broken in the most confusing way available: the device
		// routes DNS into the tunnel because the resolver is in its
		// AllowedIPs, and the gateway drops it because the resolver is
		// not in the nftables accepts. Every lookup times out on a VPN
		// that reports itself connected.
		_, cidrs, err = a.dnsFor(r.Context(), p.id, cidrs)
		if err != nil {
			a.serverError(w, "node peers dns", err)
			return
		}
		// Virtual destinations, and the policy's NAT flag.
		//
		// The forward ACL must permit the *real* address, since DNAT runs
		// before it. So each rewrite's real side is appended to cidrs;
		// the virtual side is what the phone was told and what the
		// prerouting rule matches.
		vhosts, err := a.cfg.Policies.VirtualHostsForDevice(r.Context(), p.id)
		if err != nil {
			a.serverError(w, "node peers: virtual hosts", err)
			return
		}
		var rewrites []nodeRewriteJSON
		for _, vh := range vhosts {
			rewrites = append(rewrites, nodeRewriteJSON{Virtual: vh.VirtualIP, Real: vh.RealIP})
			cidrs = append(cidrs, vh.RealIP+"/32")
		}

		var natCIDRs []string
		if pol, _ := a.cfg.Policies.ForDevice(r.Context(), p.id); pol != nil && pol.SourceNAT {
			natCIDRs = cidrs
		}

		rules, err := a.cfg.Policies.GetEffectiveRules(r.Context(), p.id)
		if err != nil {
			a.serverError(w, "node peers rules", err)
			return
		}
		out := nodePeerJSON{
			DeviceID:    p.id.String(),
			PublicKey:   base64.StdEncoding.EncodeToString(p.pubKey),
			Status:      p.status,
			PolicyBound: bound,
			PSK:         base64.StdEncoding.EncodeToString(p.psk),
			DestCIDRs:   cidrs,
			Rules:       toNodeRuleJSON(rules),
			Rewrites:    rewrites,
			NATCIDRs:    natCIDRs,
		}
		if len(p.ipv4Raw) == 4 {
			if a4, ok := netip.AddrFromSlice(p.ipv4Raw); ok {
				out.IPv4 = a4.String()
			}
		}
		if len(p.ipv6Raw) == 16 {
			if a6, ok := netip.AddrFromSlice(p.ipv6Raw); ok {
				out.IPv6 = a6.String()
			}
		}
		peers = append(peers, out)
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"node_id":      node.ID.String(),
		"hostname":     node.Hostname,
		"generated_at": time.Now().UTC().Format(time.RFC3339),
		"peers":        peers,
	})
}

func toNodeRuleJSON(rules []policies.Rule) []nodeRuleJSON {
	if len(rules) == 0 {
		return nil
	}
	out := make([]nodeRuleJSON, 0, len(rules))
	for _, r := range rules {
		j := nodeRuleJSON{
			Action:   r.Action,
			Dst:      r.Dst.String(),
			Protocol: r.Protocol,
		}
		if r.HasPorts() {
			j.PortMin = r.PortMin
			j.PortMax = r.PortMax
			// A rule with only a min is a single-port rule. Normalising
			// here keeps the nftables renderer from having to special-case
			// `port_max == 0`, which would otherwise render as the
			// nonsensical range 443-0.
			if j.PortMax == 0 {
				j.PortMax = j.PortMin
			}
			if j.PortMin == 0 {
				j.PortMin = j.PortMax
			}
		}
		out = append(out, j)
	}
	return out
}

// nodeRelayToken mints a relay credential for the authenticated gateway.
//
// This is the server-side half of P0-4. The gateway needs a `node:` relay
// token to open its outbound WebSocket to the relay VPS, but before
// 0.10.0 there was no way to obtain one — `signRelayToken` supported the
// `node:` prefix and `relayVerifyDataNode` would verify it, yet nothing
// issued it. Gateways behind a firewall that blocks inbound UDP therefore
// had no reachable path at all.
func (a *API) nodeRelayToken(w http.ResponseWriter, r *http.Request) {
	node := nodeFromContext(r.Context())
	tok, err := a.signRelayToken(relayTokenPrefixNode + node.ID.String())
	if err != nil {
		if strings.Contains(err.Error(), "not configured") {
			writeError(w, http.StatusServiceUnavailable,
				"relay is not configured on this controller (set RELAY_SIGNING_KEY)")
			return
		}
		a.serverError(w, "sign node relay token", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"token":      tok,
		"node_id":    node.ID.String(),
		"expires_in": 86400, // signRelayToken gives node tokens 24h
	})
}

// SetNodeAgentToken stores the SHA-256 of a freshly issued agent token.
// Exposed for the provisioning CLI in cmd/migrate.
//
// Returns ErrNodeNotFound when the hostname doesn't resolve to a node, so
// the CLI can print a useful message instead of reporting success on a
// typo'd hostname.
func SetNodeAgentToken(ctx context.Context, db *sql.DB, hostname, token string) error {
	sum := sha256.Sum256([]byte(token))
	res, err := db.ExecContext(ctx, `
		UPDATE nodes
		   SET agent_token_hash = ?, agent_token_set_at = CURRENT_TIMESTAMP(6)
		 WHERE hostname = ? AND deleted_at IS NULL`,
		sum[:], hostname)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNodeNotFound
	}
	return nil
}

// ErrNodeNotFound is returned by SetNodeAgentToken for an unknown hostname.
var ErrNodeNotFound = errors.New("node not found")
