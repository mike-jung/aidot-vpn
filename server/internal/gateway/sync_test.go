package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

type recordedCall struct {
	Name  string
	Args  []string
	Stdin string
}

type fakeRunner struct {
	mu       sync.Mutex
	calls    []recordedCall
	dump     string
	failNft  bool
	failWG   bool
	nftCount int
}

func (f *fakeRunner) Run(_ context.Context, name string, args []string, stdin string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, recordedCall{Name: name, Args: args, Stdin: stdin})

	if name == "nft" {
		f.nftCount++
		if f.failNft {
			return "syntax error", errors.New("exit 1")
		}
		return "", nil
	}
	if name == "wg" && len(args) > 1 && args[0] == "show" {
		return f.dump, nil
	}
	if name == "wg" && f.failWG {
		return "", errors.New("exit 1")
	}
	return "", nil
}

func (f *fakeRunner) names() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, c := range f.calls {
		out = append(out, c.Name)
	}
	return out
}

func (f *fakeRunner) wgArgs() [][]string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out [][]string
	for _, c := range f.calls {
		if c.Name == "wg" && len(c.Args) > 0 && c.Args[0] == "set" {
			out = append(out, c.Args)
		}
	}
	return out
}

func testServer(t *testing.T, peers []peerWire) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer node-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if r.URL.Path != "/node/peers" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode(peersResponse{
			NodeID: "node1", Hostname: "gw1", Peers: peers,
		})
	}))
}

func newSyncer(url string, r *fakeRunner) *Syncer {
	return &Syncer{
		ControllerURL: url,
		NodeToken:     "node-token",
		WGInterface:   "wg0",
		Runner:        r,
		HTTP:          http.DefaultClient,
	}
}

func TestSyncAppliesRulesBeforePeers(t *testing.T) {
	srv := testServer(t, []peerWire{{
		DeviceID: "d1", PublicKey: "pubkey1", IPv4: "10.78.0.5",
		Status: "active", PolicyBound: true, DestCIDRs: []string{"10.10.5.20/32"},
	}})
	defer srv.Close()

	r := &fakeRunner{dump: "iface-line\n"}
	if err := newSyncer(srv.URL, r).SyncOnce(context.Background()); err != nil {
		t.Fatalf("sync: %v", err)
	}

	names := r.names()
	nftIdx, wgSetIdx := -1, -1
	for i, c := range r.calls {
		if c.Name == "nft" && nftIdx < 0 {
			nftIdx = i
		}
		if c.Name == "wg" && len(c.Args) > 0 && c.Args[0] == "set" && wgSetIdx < 0 {
			wgSetIdx = i
		}
	}
	if nftIdx < 0 || wgSetIdx < 0 {
		t.Fatalf("expected both nft and wg set, got %v", names)
	}
	if nftIdx > wgSetIdx {
		t.Error("nftables must be applied before adding the peer, " +
			"or the peer can forward traffic against a stale ruleset")
	}
}

func TestFailedNftApplyIsRetriedNextCycle(t *testing.T) {
	srv := testServer(t, []peerWire{{
		DeviceID: "d1", PublicKey: "pubkey1", IPv4: "10.78.0.5",
		Status: "active", PolicyBound: true, DestCIDRs: []string{"10.10.5.20/32"},
	}})
	defer srv.Close()

	r := &fakeRunner{dump: "iface-line\n", failNft: true}
	s := newSyncer(srv.URL, r)

	if err := s.SyncOnce(context.Background()); err == nil {
		t.Fatal("expected error when nft fails")
	}
	// A failed apply must not be cached as "already applied".
	if err := s.SyncOnce(context.Background()); err == nil {
		t.Fatal("expected error on retry too")
	}
	if r.nftCount < 2 {
		t.Errorf("failed ruleset must be retried, nft called %d times", r.nftCount)
	}
}

func TestFailedNftApplySkipsPeerInstall(t *testing.T) {
	srv := testServer(t, []peerWire{{
		DeviceID: "d1", PublicKey: "pubkey1", IPv4: "10.78.0.5",
		Status: "active", PolicyBound: true, DestCIDRs: []string{"10.10.5.20/32"},
	}})
	defer srv.Close()

	r := &fakeRunner{dump: "iface-line\n", failNft: true}
	_ = newSyncer(srv.URL, r).SyncOnce(context.Background())

	if len(r.wgArgs()) > 0 {
		t.Error("peer must not be installed when its enforcement ruleset failed to load")
	}
}

func TestUnchangedRulesetIsNotReapplied(t *testing.T) {
	srv := testServer(t, []peerWire{{
		DeviceID: "d1", PublicKey: "pubkey1", IPv4: "10.78.0.5",
		Status: "active", PolicyBound: true, DestCIDRs: []string{"10.10.5.20/32"},
	}})
	defer srv.Close()

	r := &fakeRunner{dump: "iface\npubkey1\t(none)\t(none)\t10.78.0.5/32\t0\t0\t0\toff\n"}
	s := newSyncer(srv.URL, r)

	for i := 0; i < 3; i++ {
		if err := s.SyncOnce(context.Background()); err != nil {
			t.Fatalf("sync %d: %v", i, err)
		}
	}
	if r.nftCount != 1 {
		t.Errorf("identical policy must apply once, got %d applies", r.nftCount)
	}
}

func TestStalePeerIsRemoved(t *testing.T) {
	srv := testServer(t, []peerWire{{
		DeviceID: "d1", PublicKey: "keep", IPv4: "10.78.0.5",
		Status: "active", PolicyBound: true,
	}})
	defer srv.Close()

	r := &fakeRunner{dump: "iface\n" +
		"keep\t(none)\t(none)\t10.78.0.5/32\t0\t0\t0\toff\n" +
		"revoked\t(none)\t(none)\t10.78.0.9/32\t0\t0\t0\toff\n"}
	if err := newSyncer(srv.URL, r).SyncOnce(context.Background()); err != nil {
		t.Fatalf("sync: %v", err)
	}

	var removed bool
	for _, c := range r.calls {
		if c.Name == "wg" && len(c.Args) >= 5 &&
			c.Args[2] == "peer" && c.Args[3] == "revoked" && c.Args[4] == "remove" {
			removed = true
		}
	}
	if !removed {
		t.Error("a peer the controller no longer lists must be removed from wg")
	}
}

func TestUnboundPeerStillGetsWireGuardPeer(t *testing.T) {
	srv := testServer(t, []peerWire{{
		DeviceID: "d1", PublicKey: "pubkey1", IPv4: "10.78.0.5",
		Status: "active", PolicyBound: false,
	}})
	defer srv.Close()

	r := &fakeRunner{dump: "iface-line\n"}
	if err := newSyncer(srv.URL, r).SyncOnce(context.Background()); err != nil {
		t.Fatalf("sync: %v", err)
	}

	// The peer exists so the device can handshake and see its traffic
	// dropped (diagnosable) rather than failing to connect (looks like a
	// broken key). Enforcement lives in the ruleset, not in peer absence.
	if len(r.wgArgs()) == 0 {
		t.Error("unbound peer should still be installed as a wg peer")
	}
	var nftScript string
	for _, c := range r.calls {
		if c.Name == "nft" {
			nftScript = c.Stdin
		}
	}
	if !strings.Contains(nftScript, "ip saddr 10.78.0.5/32 drop") {
		t.Errorf("unbound peer must be dropped in the ruleset:\n%s", nftScript)
	}
}

func TestBadTokenIsAnError(t *testing.T) {
	srv := testServer(t, nil)
	defer srv.Close()

	r := &fakeRunner{dump: "iface-line\n"}
	s := newSyncer(srv.URL, r)
	s.NodeToken = "wrong"

	if err := s.SyncOnce(context.Background()); err == nil {
		t.Fatal("expected auth failure")
	}
	if r.nftCount != 0 {
		t.Error("must not touch the firewall when the controller rejected us")
	}
	if got := s.Stats().PollErrors; got != 1 {
		t.Errorf("expected 1 poll error, got %d", got)
	}
}

// A controller outage must leave the last-known-good ruleset in place.
// Flushing to "deny all" on a transient network blip would take down
// legitimate clinical traffic; flushing to "allow all" would be a
// security failure. Doing nothing is correct.
func TestControllerOutageLeavesRulesetIntact(t *testing.T) {
	srv := testServer(t, nil)
	srv.Close() // dead server

	r := &fakeRunner{dump: "iface-line\n"}
	s := newSyncer(srv.URL, r)
	if err := s.SyncOnce(context.Background()); err == nil {
		t.Fatal("expected transport error")
	}
	for _, c := range r.calls {
		if c.Name == "nft" {
			t.Fatal("must not rewrite the ruleset when the controller is unreachable")
		}
	}
}
