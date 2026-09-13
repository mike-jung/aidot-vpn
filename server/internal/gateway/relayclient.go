package gateway

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// RelayClient is the gateway's outbound connection to the relay VPS.
//
// Why this exists: the hospital's gateway sits behind a firewall that
// does not accept inbound UDP/52840, and the phone is on LTE behind
// carrier CGNAT. Neither side can be dialled. Both must dial *out* to a
// rendezvous point on TCP/443.
//
// Before 0.10.0 only half of that existed. The relay server (cmd/relay)
// and the phone's RelayClient.kt were both implemented, and the
// controller could even verify a `node:` relay token — but nothing ever
// issued one and no code dialled the relay from the gateway side. A
// phone on LTE would connect to the relay and find no node to be bridged
// to.
//
// Data flow once connected:
//
//	phone(LTE) --wss--> relay <--wss-- gateway --udp--> wg0 :52840
//
// The relay tags each phone with a session ID. We keep one local UDP
// socket per session so the kernel's WireGuard sees each phone as a
// distinct source address, exactly as it would over real UDP. Replies
// come back on that same socket and are tagged with the session ID on
// the way out.
//
// The relay only ever sees WireGuard ciphertext; it holds no keys.
type RelayClient struct {
	// RelayURL is the relay's base URL, e.g. "wss://relay.example.com".
	RelayURL string
	// ControllerURL and NodeToken are used to mint the relay credential.
	ControllerURL string
	NodeToken     string
	// WGEndpoint is the local WireGuard listener, e.g. "127.0.0.1:52840".
	WGEndpoint string
	// SessionIdle bounds how long an idle per-session UDP socket lives.
	SessionIdle time.Duration
	HTTP        *http.Client
	Logger      *slog.Logger

	mu       sync.Mutex
	sessions map[string]*relaySession
	conn     *wsConn
}

type relaySession struct {
	udp      *net.UDPConn
	lastSeen time.Time
}

// Run maintains the relay connection, reconnecting with backoff until
// ctx is cancelled.
func (c *RelayClient) Run(ctx context.Context) error {
	if c.Logger == nil {
		c.Logger = slog.Default()
	}
	if c.HTTP == nil {
		c.HTTP = &http.Client{Timeout: 20 * time.Second}
	}
	if c.WGEndpoint == "" {
		c.WGEndpoint = "127.0.0.1:52840"
	}
	if c.SessionIdle <= 0 {
		c.SessionIdle = 3 * time.Minute
	}
	c.sessions = map[string]*relaySession{}

	go c.reapSessions(ctx)

	backoff := time.Second
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		err := c.connectAndServe(ctx)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		c.Logger.Warn("relay connection ended; reconnecting",
			"err", errString(err), "backoff", backoff)

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(backoff):
		}
		// Cap the backoff low. A gateway that stays disconnected is a
		// gateway whose LTE users cannot reach the hospital at all, so
		// we prefer to keep retrying briskly rather than backing off to
		// minute-scale delays.
		backoff *= 2
		if backoff > 30*time.Second {
			backoff = 30 * time.Second
		}
	}
}

func (c *RelayClient) connectAndServe(ctx context.Context) error {
	token, nodeID, err := c.mintToken(ctx)
	if err != nil {
		return fmt.Errorf("mint relay token: %w", err)
	}

	ws, err := dialWebSocket(ctx, c.RelayURL+"/ws/data-node", token)
	if err != nil {
		return fmt.Errorf("dial relay: %w", err)
	}
	defer ws.close()

	c.mu.Lock()
	c.conn = ws
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		c.conn = nil
		c.mu.Unlock()
	}()

	// Announce ourselves. The relay already authenticated us at upgrade
	// time; this is belt-and-braces so a relay that later requires an
	// explicit hello stays compatible.
	if err := ws.sendFrame(relayFrameHello, nil, []byte(nodeID)); err != nil {
		return fmt.Errorf("hello: %w", err)
	}
	c.Logger.Info("relay connected", "relay", c.RelayURL, "node", short(nodeID))

	go c.keepalive(ctx, ws)

	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		t, header, data, err := ws.readFrame()
		if err != nil {
			return err
		}
		switch t {
		case relayFrameData:
			sessionID := string(header)
			if sessionID == "" {
				continue
			}
			if err := c.toWireGuard(ctx, sessionID, data); err != nil {
				c.Logger.Debug("relay->wg failed",
					"session", short(sessionID), "err", err.Error())
			}
		case relayFramePing:
			_ = ws.sendFrame(relayFramePing, nil, nil)
		case relayFrameError:
			return fmt.Errorf("relay error: %s", string(data))
		case relayFrameHello:
			// Ack. Nothing to do.
		}
	}
}

// toWireGuard forwards one ciphertext packet into the local WG listener,
// creating the session's UDP socket on first use.
func (c *RelayClient) toWireGuard(ctx context.Context, sessionID string, packet []byte) error {
	c.mu.Lock()
	sess, ok := c.sessions[sessionID]
	if !ok {
		addr, err := net.ResolveUDPAddr("udp", c.WGEndpoint)
		if err != nil {
			c.mu.Unlock()
			return err
		}
		udp, err := net.DialUDP("udp", nil, addr)
		if err != nil {
			c.mu.Unlock()
			return err
		}
		sess = &relaySession{udp: udp}
		c.sessions[sessionID] = sess
		c.mu.Unlock()
		go c.fromWireGuard(ctx, sessionID, sess)
	} else {
		c.mu.Unlock()
	}

	c.mu.Lock()
	sess.lastSeen = time.Now()
	c.mu.Unlock()

	_, err := sess.udp.Write(packet)
	return err
}

// fromWireGuard pumps replies from wg0 back to the relay, tagged with the
// session they belong to.
func (c *RelayClient) fromWireGuard(ctx context.Context, sessionID string, sess *relaySession) {
	buf := make([]byte, 65535)
	for {
		if ctx.Err() != nil {
			return
		}
		_ = sess.udp.SetReadDeadline(time.Now().Add(30 * time.Second))
		n, err := sess.udp.Read(buf)
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				// Idle, not broken. The reaper decides when to close.
				c.mu.Lock()
				_, alive := c.sessions[sessionID]
				c.mu.Unlock()
				if !alive {
					return
				}
				continue
			}
			return
		}

		c.mu.Lock()
		sess.lastSeen = time.Now()
		ws := c.conn
		c.mu.Unlock()
		if ws == nil {
			return
		}
		if err := ws.sendFrame(relayFrameData, []byte(sessionID), buf[:n]); err != nil {
			return
		}
	}
}

// reapSessions closes UDP sockets for phones that stopped talking.
// Without this a gateway accumulates one socket per phone that ever
// connected, and a busy hospital would exhaust its file descriptors.
func (c *RelayClient) reapSessions(ctx context.Context) {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			cutoff := time.Now().Add(-c.SessionIdle)
			c.mu.Lock()
			for id, s := range c.sessions {
				if s.lastSeen.Before(cutoff) {
					_ = s.udp.Close()
					delete(c.sessions, id)
				}
			}
			c.mu.Unlock()
		}
	}
}

func (c *RelayClient) keepalive(ctx context.Context, ws *wsConn) {
	t := time.NewTicker(20 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := ws.sendFrame(relayFramePing, nil, nil); err != nil {
				return
			}
		}
	}
}

// mintToken asks the controller for a `node:` relay credential.
func (c *RelayClient) mintToken(ctx context.Context) (token, nodeID string, err error) {
	u := strings.TrimRight(c.ControllerURL, "/") + "/node/relay-token"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, nil)
	if err != nil {
		return "", "", err
	}
	req.Header.Set("Authorization", "Bearer "+c.NodeToken)

	res, err := c.HTTP.Do(req)
	if err != nil {
		return "", "", err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(res.Body, 512))
		return "", "", fmt.Errorf("controller returned %s: %s",
			res.Status, strings.TrimSpace(string(body)))
	}
	var out struct {
		Token  string `json:"token"`
		NodeID string `json:"node_id"`
	}
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		return "", "", err
	}
	if out.Token == "" {
		return "", "", errors.New("controller returned an empty relay token")
	}
	return out.Token, out.NodeID, nil
}

// ----- Minimal RFC 6455 client ---------------------------------------------
//
// Mirrors the hand-rolled server framing in internal/relay/conn.go rather
// than adding gorilla/websocket. The one asymmetry that matters:
// client-to-server frames MUST be masked (RFC 6455 §5.3), while the
// server's frames to us are not. A relay built on the standard library
// will reject an unmasked client frame, so this is not optional.

const (
	relayFrameHello uint8 = 1
	relayFrameData  uint8 = 2
	relayFrameError uint8 = 3
	relayFramePing  uint8 = 4
)

const (
	wsOpBinary = 0x2
	wsOpClose  = 0x8
	wsOpPing   = 0x9
	wsOpPong   = 0xA
)

type wsConn struct {
	netConn net.Conn
	reader  *bufio.Reader
	writeMu sync.Mutex
	closed  bool
}

func dialWebSocket(ctx context.Context, rawURL, token string) (*wsConn, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}
	var (
		useTLS bool
		port   string
	)
	switch u.Scheme {
	case "wss", "https":
		useTLS, port = true, "443"
	case "ws", "http":
		useTLS, port = false, "80"
	default:
		return nil, fmt.Errorf("unsupported scheme %q", u.Scheme)
	}
	host := u.Host
	if u.Port() == "" {
		host = net.JoinHostPort(u.Hostname(), port)
	}

	d := &net.Dialer{Timeout: 15 * time.Second}
	var conn net.Conn
	conn, err = d.DialContext(ctx, "tcp", host)
	if err != nil {
		return nil, err
	}
	if useTLS {
		tc := tls.Client(conn, &tls.Config{ServerName: u.Hostname(), MinVersion: tls.VersionTLS12})
		if err := tc.HandshakeContext(ctx); err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("tls handshake: %w", err)
		}
		conn = tc
	}

	var keyRaw [16]byte
	if _, err := rand.Read(keyRaw[:]); err != nil {
		_ = conn.Close()
		return nil, err
	}
	key := base64.StdEncoding.EncodeToString(keyRaw[:])

	path := u.RequestURI()
	if path == "" {
		path = "/"
	}
	var req strings.Builder
	fmt.Fprintf(&req, "GET %s HTTP/1.1\r\n", path)
	fmt.Fprintf(&req, "Host: %s\r\n", u.Host)
	req.WriteString("Upgrade: websocket\r\n")
	req.WriteString("Connection: Upgrade\r\n")
	fmt.Fprintf(&req, "Sec-WebSocket-Key: %s\r\n", key)
	req.WriteString("Sec-WebSocket-Version: 13\r\n")
	fmt.Fprintf(&req, "Authorization: Bearer %s\r\n", token)
	req.WriteString("\r\n")

	_ = conn.SetWriteDeadline(time.Now().Add(15 * time.Second))
	if _, err := io.WriteString(conn, req.String()); err != nil {
		_ = conn.Close()
		return nil, err
	}
	_ = conn.SetWriteDeadline(time.Time{})

	br := bufio.NewReader(conn)
	_ = conn.SetReadDeadline(time.Now().Add(15 * time.Second))
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodGet})
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	_ = conn.SetReadDeadline(time.Time{})
	if resp.StatusCode != http.StatusSwitchingProtocols {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
		_ = conn.Close()
		return nil, fmt.Errorf("relay refused upgrade: %s %s",
			resp.Status, strings.TrimSpace(string(body)))
	}

	// Verify the accept value. Skipping this would let any HTTP endpoint
	// that happens to answer 101 be treated as a relay.
	h := sha1.New()
	h.Write([]byte(key))
	h.Write([]byte("258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	want := base64.StdEncoding.EncodeToString(h.Sum(nil))
	if resp.Header.Get("Sec-WebSocket-Accept") != want {
		_ = conn.Close()
		return nil, errors.New("relay returned a bad Sec-WebSocket-Accept")
	}

	return &wsConn{netConn: conn, reader: br}, nil
}

func (c *wsConn) readFrame() (uint8, []byte, []byte, error) {
	msg, err := c.readMessage()
	if err != nil {
		return 0, nil, nil, err
	}
	if len(msg) < 3 {
		return 0, nil, nil, errors.New("frame too short")
	}
	t := msg[0]
	hdrLen := int(binary.BigEndian.Uint16(msg[1:3]))
	if 3+hdrLen+2 > len(msg) {
		return 0, nil, nil, errors.New("frame header exceeds message")
	}
	header := msg[3 : 3+hdrLen]
	dl := 3 + hdrLen
	dataLen := int(binary.BigEndian.Uint16(msg[dl : dl+2]))
	start := dl + 2
	if start+dataLen > len(msg) {
		return 0, nil, nil, errors.New("frame data exceeds message")
	}
	return t, header, msg[start : start+dataLen], nil
}

func (c *wsConn) sendFrame(t uint8, header, data []byte) error {
	if len(header) > 0xFFFF || len(data) > 0xFFFF {
		return errors.New("frame field too large")
	}
	buf := make([]byte, 0, 5+len(header)+len(data))
	buf = append(buf, t)
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(header)))
	buf = append(buf, header...)
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(data)))
	buf = append(buf, data...)

	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.closed {
		return errors.New("conn closed")
	}
	_ = c.netConn.SetWriteDeadline(time.Now().Add(30 * time.Second))
	return writeMaskedBinary(c.netConn, buf)
}

func (c *wsConn) readMessage() ([]byte, error) {
	for {
		_ = c.netConn.SetReadDeadline(time.Now().Add(120 * time.Second))
		h1, err := c.reader.ReadByte()
		if err != nil {
			return nil, err
		}
		h2, err := c.reader.ReadByte()
		if err != nil {
			return nil, err
		}
		fin := h1&0x80 != 0
		opcode := h1 & 0x0F
		masked := h2&0x80 != 0
		n := uint64(h2 & 0x7F)
		switch n {
		case 126:
			var b [2]byte
			if _, err := io.ReadFull(c.reader, b[:]); err != nil {
				return nil, err
			}
			n = uint64(binary.BigEndian.Uint16(b[:]))
		case 127:
			var b [8]byte
			if _, err := io.ReadFull(c.reader, b[:]); err != nil {
				return nil, err
			}
			n = binary.BigEndian.Uint64(b[:])
		}
		if n > 1<<20 {
			return nil, errors.New("frame too large")
		}
		var mask [4]byte
		if masked {
			if _, err := io.ReadFull(c.reader, mask[:]); err != nil {
				return nil, err
			}
		}
		payload := make([]byte, n)
		if _, err := io.ReadFull(c.reader, payload); err != nil {
			return nil, err
		}
		if masked {
			for i := range payload {
				payload[i] ^= mask[i%4]
			}
		}
		switch opcode {
		case wsOpBinary:
			if !fin {
				return nil, errors.New("fragmented frames not supported")
			}
			return payload, nil
		case wsOpClose:
			return nil, io.EOF
		case wsOpPing, wsOpPong:
			continue
		default:
			return nil, fmt.Errorf("unsupported opcode %x", opcode)
		}
	}
}

// writeMaskedBinary emits one masked binary frame, as the RFC requires of
// clients.
func writeMaskedBinary(w net.Conn, payload []byte) error {
	hdr := make([]byte, 0, 14)
	hdr = append(hdr, 0x80|wsOpBinary)
	switch {
	case len(payload) <= 125:
		hdr = append(hdr, 0x80|byte(len(payload)))
	case len(payload) <= 0xFFFF:
		hdr = append(hdr, 0x80|126)
		hdr = binary.BigEndian.AppendUint16(hdr, uint16(len(payload)))
	default:
		hdr = append(hdr, 0x80|127)
		hdr = binary.BigEndian.AppendUint64(hdr, uint64(len(payload)))
	}
	var mask [4]byte
	if _, err := rand.Read(mask[:]); err != nil {
		return err
	}
	hdr = append(hdr, mask[:]...)
	if _, err := w.Write(hdr); err != nil {
		return err
	}
	masked := make([]byte, len(payload))
	for i := range payload {
		masked[i] = payload[i] ^ mask[i%4]
	}
	_, err := w.Write(masked)
	return err
}

func (c *wsConn) close() error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true
	return c.netConn.Close()
}

func errString(err error) string {
	if err == nil {
		return "<nil>"
	}
	return err.Error()
}
