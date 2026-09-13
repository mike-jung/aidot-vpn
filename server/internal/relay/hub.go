// Package relay implements a WireGuard packet relay over WebSocket.
//
// What it does:
//
//	A small process intended to run on a cloud VPS with a public IP. Two
//	classes of clients connect to it over WebSocket (port 443):
//	  - "data-node" clients: the wg-data-node container running behind
//	    a customer NAT. Outbound TCP/443 → relay. Identified by a token
//	    matching its registered node_id in the controller.
//	  - "mobile" clients: the Android/iOS app, also behind NAT (mobile
//	    carrier CGNAT, public Wi-Fi, etc). Outbound TCP/443 → relay.
//	    Identified by a session token issued by the controller after
//	    OIDC login.
//
//	When a mobile peer wants to talk to a specific data-node, the relay
//	pipes its WebSocket frames to the data-node's WebSocket connection
//	and back. The frames carry WireGuard ciphertext as-is — the relay
//	never has any key material and cannot decrypt anything.
//
// Why WebSocket over TCP/443:
//
//	WireGuard's native UDP transport gets blocked or NAT-mangled by:
//	  - Korean carrier CGNAT (SKT/KT/LGU+) on mobile data
//	  - Public Wi-Fi captive portals that drop non-HTTP UDP
//	  - Strict corporate firewalls that allow only HTTPS outbound
//	WebSocket-over-TLS on port 443 looks identical to ordinary HTTPS
//	browsing traffic and traverses all of these. We don't actually use
//	TLS in this package (a fronting reverse proxy adds it); the WS
//	upgrade is enough.
//
// Trust model:
//
//	The relay sees WireGuard ciphertext only. It can correlate a
//	data-node ↔ mobile pair by token, learn how many bytes flow, and
//	infer when each side is online — but it cannot decrypt traffic.
//	Compromise of the relay is equivalent to compromise of any router
//	on the public internet, NOT to compromise of the controller or
//	wg-data-node.
package relay

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"
)

// Hub manages the set of currently-connected peers and routes ciphertext
// frames between them. One Hub instance per relay process.
type Hub struct {
	logger     *slog.Logger
	authTokens AuthLookup

	mu       sync.RWMutex
	dataNode map[string]*conn // node_id (hex) -> conn
	mobile   map[string]*conn // session_id  -> conn

	// nodeForMobile maps a mobile session to its target data-node.
	// Set when the mobile client sends its initial Hello frame
	// announcing which node_id it wants to reach.
	nodeForMobile map[string]string
}

// AuthLookup verifies relay-time credentials. The relay does NOT manage
// users itself — it asks an upstream authority (the controller, in our
// architecture) whether a given token is valid and what role/identity
// it carries. This keeps user state in one place.
type AuthLookup interface {
	// VerifyDataNode confirms the bearer is allowed to register as the
	// named data-node and returns its canonical node_id.
	VerifyDataNode(ctx context.Context, token string) (nodeID string, err error)
	// VerifyMobile confirms the bearer is a registered device and returns
	// a stable session_id (typically the device_id hex).
	VerifyMobile(ctx context.Context, token string) (sessionID string, err error)
}

// NewHub builds a fresh Hub. logger may be nil (defaults to slog.Default).
func NewHub(auth AuthLookup, logger *slog.Logger) *Hub {
	if logger == nil {
		logger = slog.Default()
	}
	return &Hub{
		logger:        logger,
		authTokens:    auth,
		dataNode:      make(map[string]*conn),
		mobile:        make(map[string]*conn),
		nodeForMobile: make(map[string]string),
	}
}

// registerDataNode stores a connection in the data-node table, replacing
// any prior connection for the same node_id (caller's prior connection
// is closed). Returns a cleanup func to deregister on disconnect.
func (h *Hub) registerDataNode(nodeID string, c *conn) func() {
	h.mu.Lock()
	if old, ok := h.dataNode[nodeID]; ok {
		_ = old.close()
	}
	h.dataNode[nodeID] = c
	h.mu.Unlock()
	h.logger.Info("data-node connected", "node", shortID(nodeID))
	return func() {
		h.mu.Lock()
		// Only delete if we're still the registered conn — a later
		// reconnection might have replaced us already.
		if h.dataNode[nodeID] == c {
			delete(h.dataNode, nodeID)
		}
		h.mu.Unlock()
		h.logger.Info("data-node disconnected", "node", shortID(nodeID))
	}
}

// registerMobile stores a mobile session and binds it to its target
// node. Returns a cleanup func.
func (h *Hub) registerMobile(sessionID, nodeID string, c *conn) func() {
	h.mu.Lock()
	if old, ok := h.mobile[sessionID]; ok {
		_ = old.close()
	}
	h.mobile[sessionID] = c
	h.nodeForMobile[sessionID] = nodeID
	h.mu.Unlock()
	h.logger.Info("mobile connected", "session", shortID(sessionID), "node", shortID(nodeID))
	return func() {
		h.mu.Lock()
		if h.mobile[sessionID] == c {
			delete(h.mobile, sessionID)
			delete(h.nodeForMobile, sessionID)
		}
		h.mu.Unlock()
		h.logger.Info("mobile disconnected", "session", shortID(sessionID))
	}
}

// forwardFromMobile sends a packet from a mobile peer to its target
// data-node. Drops silently when the data-node is offline — the WG
// keepalive on the mobile side will retry.
func (h *Hub) forwardFromMobile(sessionID string, packet []byte) error {
	h.mu.RLock()
	nodeID, ok := h.nodeForMobile[sessionID]
	if !ok {
		h.mu.RUnlock()
		return errors.New("mobile session has no target node")
	}
	dest := h.dataNode[nodeID]
	h.mu.RUnlock()
	if dest == nil {
		// Best-effort: the mobile side will retry via WG keepalive.
		return nil
	}
	// Tag the packet with the mobile session ID so the data-node knows
	// which peer it's from. The wg-data-node maintains an internal
	// session->peer mapping.
	return dest.sendFrame(frameTypeData, []byte(sessionID), packet)
}

// forwardFromDataNode sends a packet from the data-node to one of its
// connected mobile peers, identified by sessionID inside the frame.
func (h *Hub) forwardFromDataNode(nodeID, sessionID string, packet []byte) error {
	h.mu.RLock()
	dest := h.mobile[sessionID]
	h.mu.RUnlock()
	if dest == nil {
		return nil // peer offline; WG retransmits
	}
	return dest.sendFrame(frameTypeData, nil, packet)
}

// ServeHTTP is the WebSocket entry point. The role is selected by URL path:
//   - /ws/data-node    : data-node side
//   - /ws/mobile       : mobile side
//
// Authentication: Bearer token in the Authorization header.
func (h *Hub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/ws/data-node":
		h.handleDataNode(w, r)
	case "/ws/mobile":
		h.handleMobile(w, r)
	case "/healthz":
		_, _ = w.Write([]byte("ok"))
	default:
		http.NotFound(w, r)
	}
}

// shortID returns the first 8 chars for log readability.
func shortID(s string) string {
	if len(s) > 8 {
		return s[:8]
	}
	return s
}

// fingerprint returns a short hash of a token for logging without
// echoing the secret.
func fingerprint(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:4])
}

// frameType discriminates the kinds of WebSocket frames the relay
// understands. The wire format is documented in conn.go.
type frameType uint8

const (
	frameTypeHello frameType = 1 // initial handshake
	frameTypeData  frameType = 2 // ciphertext payload
	frameTypeError frameType = 3 // server -> client error
	frameTypePing  frameType = 4 // keepalive
)

// connDeadline limits how long a peer can hold a slot without traffic
// before we reclaim it.
const connDeadline = 5 * time.Minute

// helloTimeout is how long after WS upgrade we wait for the client to
// announce itself before disconnecting them.
const helloTimeout = 10 * time.Second

// Compile-time guard: Hub satisfies http.Handler.
var _ http.Handler = (*Hub)(nil)

// _ explicit unused-import guard because we reference `fmt` only in
// generated wrappers in some builds.
var _ = fmt.Sprint
