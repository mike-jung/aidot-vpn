package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aidotvpn/server/internal/relay"
)

// fakeAuth accepts any non-empty token, echoing back a fixed identity.
type fakeAuth struct{}

func (fakeAuth) VerifyDataNode(_ context.Context, token string) (string, error) {
	if token == "" {
		return "", errNoToken
	}
	return "node-1", nil
}

func (fakeAuth) VerifyMobile(_ context.Context, token string) (string, error) {
	if token == "" {
		return "", errNoToken
	}
	return "session-abc", nil
}

var errNoToken = &authErr{}

type authErr struct{}

func (*authErr) Error() string { return "no token" }

// controllerStub serves POST /node/relay-token like the real controller.
func controllerStub(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/node/relay-token" || r.Method != http.MethodPost {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if r.Header.Get("Authorization") != "Bearer node-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"token": "relay-token-xyz", "node_id": "node-1", "expires_in": 86400,
		})
	}))
}

// TestRelayClientInteropWithRealRelay is the test that matters for P0-4.
//
// The WebSocket client here is hand-rolled to match the equally
// hand-rolled server in internal/relay. Two independent minimal RFC 6455
// implementations agreeing is not something to assume — in particular the
// client MUST mask its frames and the server MUST unmask them, and a
// mistake there produces garbled ciphertext rather than a clean error.
// So this test runs the real relay.Hub and drives it with the real
// client, end to end over a real socket.
func TestRelayClientInteropWithRealRelay(t *testing.T) {
	hub := relay.NewHub(fakeAuth{}, nil)
	relaySrv := httptest.NewServer(hub)
	defer relaySrv.Close()

	ctrl := controllerStub(t)
	defer ctrl.Close()

	// Stand in for the kernel WireGuard listener: echo every datagram
	// back with a marker, which is enough to prove the return path.
	wgAddr, wgStop := fakeWireGuard(t)
	defer wgStop()

	client := &RelayClient{
		RelayURL:      strings.Replace(relaySrv.URL, "http://", "ws://", 1),
		ControllerURL: ctrl.URL,
		NodeToken:     "node-token",
		WGEndpoint:    wgAddr,
		SessionIdle:   time.Minute,
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = client.Run(ctx) }()

	// Give the gateway a moment to register with the relay, otherwise
	// the mobile side's packet is dropped (relay drops when the target
	// node is offline, by design).
	waitFor(t, 3*time.Second, func() bool {
		client.mu.Lock()
		defer client.mu.Unlock()
		return client.conn != nil
	})

	// Now play the part of the phone.
	mobile, err := dialWebSocket(ctx,
		strings.Replace(relaySrv.URL, "http://", "ws://", 1)+"/ws/mobile", "mobile-token")
	if err != nil {
		t.Fatalf("mobile dial: %v", err)
	}
	defer mobile.close()

	// Mobile hello announces the target node.
	if err := mobile.sendFrame(relayFrameHello, nil, []byte("node-1")); err != nil {
		t.Fatalf("mobile hello: %v", err)
	}
	if ft, _, _, err := mobile.readFrame(); err != nil || ft != relayFrameHello {
		t.Fatalf("expected hello ack, got type=%d err=%v", ft, err)
	}

	payload := []byte("wireguard-ciphertext-\x00\x01\x02\xff")
	if err := mobile.sendFrame(relayFrameData, nil, payload); err != nil {
		t.Fatalf("mobile send: %v", err)
	}

	// The gateway should have pushed it into "WireGuard" and pumped the
	// echo back through the relay to us.
	done := make(chan []byte, 1)
	go func() {
		for {
			ft, _, data, err := mobile.readFrame()
			if err != nil {
				return
			}
			if ft == relayFrameData {
				done <- data
				return
			}
		}
	}()

	select {
	case got := <-done:
		want := append([]byte("echo:"), payload...)
		if !bytes.Equal(got, want) {
			t.Fatalf("round-trip corrupted:\n got %q\nwant %q", got, want)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no packet came back through the relay within 5s")
	}
}

func TestRelayClientRejectsBadAcceptHeader(t *testing.T) {
	// Any endpoint answering 101 must not be mistaken for a relay.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hj, ok := w.(http.Hijacker)
		if !ok {
			return
		}
		conn, brw, _ := hj.Hijack()
		_, _ = brw.WriteString("HTTP/1.1 101 Switching Protocols\r\n" +
			"Upgrade: websocket\r\nConnection: Upgrade\r\n" +
			"Sec-WebSocket-Accept: bogus\r\n\r\n")
		_ = brw.Flush()
		_ = conn.Close()
	}))
	defer srv.Close()

	_, err := dialWebSocket(context.Background(),
		strings.Replace(srv.URL, "http://", "ws://", 1)+"/ws/data-node", "tok")
	if err == nil {
		t.Fatal("expected the bad accept value to be rejected")
	}
	if !strings.Contains(err.Error(), "Sec-WebSocket-Accept") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestMintTokenSurfacesControllerRejection(t *testing.T) {
	ctrl := controllerStub(t)
	defer ctrl.Close()

	c := &RelayClient{ControllerURL: ctrl.URL, NodeToken: "wrong", HTTP: http.DefaultClient}
	if _, _, err := c.mintToken(context.Background()); err == nil {
		t.Fatal("expected an error for a bad node token")
	}
}

// fakeWireGuard listens on UDP and echoes with a prefix.
func fakeWireGuard(t *testing.T) (addr string, stop func()) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	done := make(chan struct{})
	go func() {
		buf := make([]byte, 65535)
		for {
			select {
			case <-done:
				return
			default:
			}
			_ = pc.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				continue
			}
			_, _ = pc.WriteTo(append([]byte("echo:"), buf[:n]...), from)
		}
	}()
	return pc.LocalAddr().String(), func() { close(done); _ = pc.Close() }
}

func waitFor(t *testing.T, d time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("condition not met within timeout")
}
