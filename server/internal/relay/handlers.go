package relay

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"
)

// extractBearer pulls a bearer token from the Authorization header. We
// also accept it as a `?token=` query param because some WebSocket
// clients (Android OkHttp) make custom-header injection awkward.
func extractBearer(r *http.Request) string {
	if h := r.Header.Get("Authorization"); h != "" {
		if strings.HasPrefix(strings.ToLower(h), "bearer ") {
			return strings.TrimSpace(h[len("bearer "):])
		}
	}
	return r.URL.Query().Get("token")
}

func (h *Hub) handleDataNode(w http.ResponseWriter, r *http.Request) {
	token := extractBearer(r)
	if token == "" {
		http.Error(w, "missing token", http.StatusUnauthorized)
		return
	}
	nodeID, err := h.authTokens.VerifyDataNode(r.Context(), token)
	if err != nil {
		h.logger.Info("data-node auth rejected",
			"token", fingerprint(token), "err", err.Error())
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	c, err := acceptWebSocket(w, r)
	if err != nil {
		h.logger.Info("ws upgrade failed", "err", err.Error())
		return
	}
	cleanup := h.registerDataNode(nodeID, c)
	defer cleanup()
	defer c.close()

	// A data-node frame's `header` field carries the destination
	// session_id (the mobile peer it's sending to). The frame's `data`
	// is the WireGuard ciphertext.
	for {
		t, header, data, err := c.readFrame()
		if err != nil {
			if !errors.Is(err, io.EOF) {
				h.logger.Debug("data-node read error", "node", shortID(nodeID), "err", err.Error())
			}
			return
		}
		switch t {
		case frameTypeData:
			sessionID := string(header)
			if err := h.forwardFromDataNode(nodeID, sessionID, data); err != nil {
				h.logger.Debug("forward to mobile failed",
					"node", shortID(nodeID), "session", shortID(sessionID), "err", err.Error())
			}
		case frameTypePing:
			_ = c.sendFrame(frameTypePing, nil, nil)
		case frameTypeHello:
			// Re-hello mid-session is a no-op; we already authed at
			// upgrade time. Ignore.
		default:
			h.logger.Debug("unknown frame type from data-node",
				"node", shortID(nodeID), "type", t)
		}
	}
}

func (h *Hub) handleMobile(w http.ResponseWriter, r *http.Request) {
	token := extractBearer(r)
	if token == "" {
		http.Error(w, "missing token", http.StatusUnauthorized)
		return
	}
	sessionID, err := h.authTokens.VerifyMobile(r.Context(), token)
	if err != nil {
		h.logger.Info("mobile auth rejected",
			"token", fingerprint(token), "err", err.Error())
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	c, err := acceptWebSocket(w, r)
	if err != nil {
		return
	}
	defer c.close()

	// First frame from a mobile peer must be Hello announcing which
	// data-node it wants to reach. We use a short timeout so that a
	// silent client doesn't hold a slot.
	helloCtx, cancel := context.WithTimeout(r.Context(), helloTimeout)
	defer cancel()

	type helloResult struct {
		t      frameType
		header []byte
		data   []byte
		err    error
	}
	res := make(chan helloResult, 1)
	go func() {
		t, hdr, d, err := c.readFrame()
		res <- helloResult{t: t, header: hdr, data: d, err: err}
	}()

	var hello helloResult
	select {
	case hello = <-res:
	case <-helloCtx.Done():
		_ = c.sendFrame(frameTypeError, nil, []byte("hello timeout"))
		return
	}
	if hello.err != nil {
		return
	}
	if hello.t != frameTypeHello {
		_ = c.sendFrame(frameTypeError, nil, []byte("first frame must be hello"))
		return
	}
	// Hello.data carries the target node_id (hex string).
	targetNodeID := string(hello.data)
	if targetNodeID == "" {
		_ = c.sendFrame(frameTypeError, nil, []byte("hello missing node_id"))
		return
	}

	cleanup := h.registerMobile(sessionID, targetNodeID, c)
	defer cleanup()

	// Acknowledge so the client can stop blocking.
	_ = c.sendFrame(frameTypeHello, nil, []byte("ok"))

	// Steady-state: forward every Data frame we receive to the bound
	// data-node. Header is unused on this path because the mapping is
	// fixed at hello time.
	for {
		t, _, data, err := c.readFrame()
		if err != nil {
			if !errors.Is(err, io.EOF) {
				h.logger.Debug("mobile read error", "session", shortID(sessionID), "err", err.Error())
			}
			return
		}
		switch t {
		case frameTypeData:
			if err := h.forwardFromMobile(sessionID, data); err != nil {
				h.logger.Debug("forward to data-node failed",
					"session", shortID(sessionID), "err", err.Error())
			}
		case frameTypePing:
			_ = c.sendFrame(frameTypePing, nil, nil)
		default:
			h.logger.Debug("unknown frame type from mobile",
				"session", shortID(sessionID), "type", t)
		}
	}
}

// keep the import used even if a build trims the Hello timeout path.
var _ = binary.BigEndian
var _ = time.Now
