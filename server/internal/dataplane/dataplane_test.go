package dataplane

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"testing"
	"time"
)

func mkPubkey(seed byte) [32]byte {
	var k [32]byte
	for i := range k {
		k[i] = seed
	}
	return k
}

func mkPeer(seed byte, ipv4 string) PeerConfig {
	prefix, _ := netip.ParsePrefix(ipv4)
	return PeerConfig{
		PublicKey:                  mkPubkey(seed),
		PSK:                        mkPubkey(seed + 0x10),
		AllowedIPs:                 []netip.Prefix{prefix},
		PersistentKeepaliveSeconds: 25,
	}
}

func TestMemoryEngine_ConfigureNewDevice(t *testing.T) {
	e := NewMemoryEngine()
	defer e.Close()

	err := e.Configure(context.Background(), "wg0", DeviceConfig{
		PrivateKey:   mkPubkey(1),
		ListenPort:   52840,
		Peers:        []PeerConfig{mkPeer(2, "10.78.0.10/32"), mkPeer(3, "10.78.0.11/32")},
		ReplacePeers: true,
	})
	if err != nil {
		t.Fatalf("Configure: %v", err)
	}
	if got := e.PeerCount("wg0"); got != 2 {
		t.Errorf("peer count: %d, want 2", got)
	}
}

func TestMemoryEngine_ReplacePeers(t *testing.T) {
	e := NewMemoryEngine()
	defer e.Close()
	ctx := context.Background()

	// First config: 3 peers
	_ = e.Configure(ctx, "wg0", DeviceConfig{
		PrivateKey: mkPubkey(1), ListenPort: 52840,
		Peers: []PeerConfig{
			mkPeer(2, "10.78.0.10/32"),
			mkPeer(3, "10.78.0.11/32"),
			mkPeer(4, "10.78.0.12/32"),
		},
		ReplacePeers: true,
	})

	// Second config: only 2 peers, ReplacePeers=true → 4 should disappear
	_ = e.Configure(ctx, "wg0", DeviceConfig{
		PrivateKey: mkPubkey(1), ListenPort: 52840,
		Peers: []PeerConfig{
			mkPeer(2, "10.78.0.10/32"),
			mkPeer(3, "10.78.0.11/32"),
		},
		ReplacePeers: true,
	})
	if got := e.PeerCount("wg0"); got != 2 {
		t.Errorf("after replace: %d peers, want 2", got)
	}
	state, _ := e.Read(ctx, "wg0")
	for _, p := range state.Peers {
		if p.PublicKey == mkPubkey(4) {
			t.Errorf("peer 4 should have been removed by ReplacePeers")
		}
	}
}

func TestMemoryEngine_ReplacePeersPreservesTelemetry(t *testing.T) {
	e := NewMemoryEngine()
	defer e.Close()
	ctx := context.Background()

	pk := mkPubkey(2)
	_ = e.Configure(ctx, "wg0", DeviceConfig{
		PrivateKey: mkPubkey(1), ListenPort: 52840,
		Peers:        []PeerConfig{mkPeer(2, "10.78.0.10/32")},
		ReplacePeers: true,
	})
	now := time.Now().UTC()
	if err := e.InjectTelemetry("wg0", pk, 1024, 2048, now,
		netip.MustParseAddrPort("203.0.113.1:52840")); err != nil {
		t.Fatalf("inject: %v", err)
	}

	// Re-apply same peer set; telemetry must survive.
	_ = e.Configure(ctx, "wg0", DeviceConfig{
		PrivateKey: mkPubkey(1), ListenPort: 52840,
		Peers:        []PeerConfig{mkPeer(2, "10.78.0.10/32")},
		ReplacePeers: true,
	})
	state, _ := e.Read(ctx, "wg0")
	if len(state.Peers) != 1 {
		t.Fatalf("expected 1 peer, got %d", len(state.Peers))
	}
	p := state.Peers[0]
	if p.RxBytes != 1024 || p.TxBytes != 2048 {
		t.Errorf("telemetry lost on re-apply: rx=%d tx=%d", p.RxBytes, p.TxBytes)
	}
}

func TestMemoryEngine_ReadUnknownDevice(t *testing.T) {
	e := NewMemoryEngine()
	if _, err := e.Read(context.Background(), "wg9"); !errors.Is(err, ErrNoDevice) {
		t.Errorf("expected ErrNoDevice, got %v", err)
	}
}

// --- Agent tests --------------------------------------------------------

// fakeController is a controllable ControllerClient for tests.
type fakeController struct {
	mu          sync.Mutex
	syncCalls   int
	reportCalls int
	syncResults []*SyncPeersResult
	syncErrors  []error
	reports     [][]ReportSessionStat
	reportErr   error
	accepted    uint32
	rejected    uint32
}

func (f *fakeController) SyncPeers(ctx context.Context, currentVersion string) (*SyncPeersResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	idx := f.syncCalls
	f.syncCalls++
	if idx < len(f.syncErrors) && f.syncErrors[idx] != nil {
		return nil, f.syncErrors[idx]
	}
	if idx < len(f.syncResults) {
		return f.syncResults[idx], nil
	}
	// Default: same version, NotModified.
	return &SyncPeersResult{Version: currentVersion, NotModified: true}, nil
}

func (f *fakeController) ReportSessions(ctx context.Context, stats []ReportSessionStat) (uint32, uint32, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reportCalls++
	f.reports = append(f.reports, append([]ReportSessionStat(nil), stats...))
	if f.reportErr != nil {
		return 0, 0, f.reportErr
	}
	return f.accepted, f.rejected, nil
}

func (f *fakeController) snapshot() (sync, report int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.syncCalls, f.reportCalls
}

func TestAgent_AppliesNewPeerSet(t *testing.T) {
	e := NewMemoryEngine()
	defer e.Close()

	fc := &fakeController{
		syncResults: []*SyncPeersResult{
			{
				Version: "v1",
				Peers: []PeerConfig{
					mkPeer(2, "10.78.0.10/32"),
					mkPeer(3, "10.78.0.11/32"),
				},
			},
		},
		accepted: 0,
	}

	a, err := NewAgent(AgentConfig{
		DeviceName:   "wg0",
		PrivateKey:   mkPubkey(1),
		ListenPort:   52840,
		SyncInterval: 50 * time.Millisecond,
		Engine:       e,
		Controller:   fc,
	})
	if err != nil {
		t.Fatalf("NewAgent: %v", err)
	}

	// Run one reconcile manually instead of starting the loop.
	a.reconcile(context.Background())

	if got := e.PeerCount("wg0"); got != 2 {
		t.Errorf("after reconcile: %d peers, want 2", got)
	}
	if a.CurrentVersion() != "v1" {
		t.Errorf("version: %q, want v1", a.CurrentVersion())
	}
	stats := a.Stats()
	if stats.SyncCount != 1 || stats.ApplyCount != 1 {
		t.Errorf("stats: %+v", stats)
	}
}

func TestAgent_SkipsApplyOnNotModified(t *testing.T) {
	e := NewMemoryEngine()
	defer e.Close()

	fc := &fakeController{
		syncResults: []*SyncPeersResult{
			{Version: "v1", Peers: []PeerConfig{mkPeer(2, "10.78.0.10/32")}},
			{Version: "v1", NotModified: true},
		},
	}

	a, _ := NewAgent(AgentConfig{
		DeviceName: "wg0",
		PrivateKey: mkPubkey(1),
		Engine:     e,
		Controller: fc,
	})

	a.reconcile(context.Background())
	a.reconcile(context.Background())

	stats := a.Stats()
	if stats.SyncCount != 2 {
		t.Errorf("sync count: %d, want 2", stats.SyncCount)
	}
	if stats.ApplyCount != 1 {
		t.Errorf("apply count: %d, want 1 (NotModified should skip apply)", stats.ApplyCount)
	}
}

func TestAgent_ReportsTelemetryAfterHandshake(t *testing.T) {
	e := NewMemoryEngine()
	defer e.Close()

	pk := mkPubkey(2)
	fc := &fakeController{
		syncResults: []*SyncPeersResult{
			{Version: "v1", Peers: []PeerConfig{mkPeer(2, "10.78.0.10/32")}},
		},
	}

	a, _ := NewAgent(AgentConfig{
		DeviceName: "wg0",
		PrivateKey: mkPubkey(1),
		Engine:     e,
		Controller: fc,
	})

	// First reconcile: configure peer (no telemetry yet -> no report).
	a.reconcile(context.Background())
	if _, r := fc.snapshot(); r != 0 {
		t.Errorf("expected 0 reports after first reconcile, got %d", r)
	}

	// Inject handshake + traffic.
	now := time.Now().UTC()
	_ = e.InjectTelemetry("wg0", pk, 5000, 7000, now,
		netip.MustParseAddrPort("203.0.113.42:52840"))

	// Second reconcile: should now report (NotModified path).
	fc.mu.Lock()
	fc.syncResults = append(fc.syncResults, &SyncPeersResult{Version: "v1", NotModified: true})
	fc.mu.Unlock()
	a.reconcile(context.Background())

	if _, r := fc.snapshot(); r != 1 {
		t.Errorf("expected 1 report after handshake, got %d", r)
	}
	fc.mu.Lock()
	if len(fc.reports) != 1 || len(fc.reports[0]) != 1 {
		t.Fatalf("unexpected report shape: %+v", fc.reports)
	}
	rep := fc.reports[0][0]
	fc.mu.Unlock()
	if rep.PeerPublicKey != pk {
		t.Error("wrong peer in report")
	}
	if rep.RxBytes != 5000 || rep.TxBytes != 7000 {
		t.Errorf("telemetry mismatch in report: rx=%d tx=%d", rep.RxBytes, rep.TxBytes)
	}
}

func TestAgent_ContinuesAfterSyncError(t *testing.T) {
	e := NewMemoryEngine()
	defer e.Close()
	fc := &fakeController{
		syncErrors: []error{errors.New("boom"), nil},
		syncResults: []*SyncPeersResult{
			nil, // first call returns the error above
			{Version: "v1", Peers: []PeerConfig{mkPeer(2, "10.78.0.10/32")}},
		},
	}
	a, _ := NewAgent(AgentConfig{
		DeviceName: "wg0",
		PrivateKey: mkPubkey(1),
		Engine:     e,
		Controller: fc,
	})

	a.reconcile(context.Background())
	a.reconcile(context.Background())

	stats := a.Stats()
	if stats.SyncErrors != 1 {
		t.Errorf("sync errors: %d, want 1", stats.SyncErrors)
	}
	if stats.ApplyCount != 1 {
		t.Errorf("apply count: %d, want 1 (second call should succeed)", stats.ApplyCount)
	}
}

func TestAgent_RunStopsOnContextCancel(t *testing.T) {
	e := NewMemoryEngine()
	defer e.Close()
	fc := &fakeController{}

	a, _ := NewAgent(AgentConfig{
		DeviceName:   "wg0",
		PrivateKey:   mkPubkey(1),
		SyncInterval: 5 * time.Millisecond,
		Engine:       e,
		Controller:   fc,
	})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		_ = a.Run(ctx)
		close(done)
	}()
	time.Sleep(30 * time.Millisecond)
	cancel()

	select {
	case <-done:
		// good
	case <-time.After(time.Second):
		t.Fatal("agent did not stop on ctx cancel within 1s")
	}
	stats := a.Stats()
	if stats.SyncCount < 2 {
		t.Logf("sync count after 30ms with 5ms interval: %d (informational)", stats.SyncCount)
	}
}
