// The sync loop is the data-node agent's reconciler.
//
// On every tick it:
//
//  1. Calls ControllerClient.SyncPeers with the version we last applied.
//     If the controller responds NotModified, we skip apply and proceed
//     directly to telemetry.
//  2. Otherwise, applies the new peer list to the local Engine
//     (ReplacePeers=true: the controller is authoritative).
//  3. Reads device state via Engine.Read() and pushes session telemetry
//     back via ControllerClient.ReportSessions.
//
// Errors at any step are logged via slog and do NOT stop the loop —
// we want the agent to keep retrying through transient failures. The
// only thing that exits the loop is a context cancellation (SIGTERM).
package dataplane

import (
	"context"
	"log/slog"
	"sync/atomic"
	"time"
)

// ControllerClient is the subset of NodeService methods the sync loop uses.
// Defining it as an interface (instead of importing the generated Connect
// client directly) lets us test the agent without standing up a server.
type ControllerClient interface {
	SyncPeers(ctx context.Context, currentVersion string) (*SyncPeersResult, error)
	ReportSessions(ctx context.Context, stats []ReportSessionStat) (accepted, rejected uint32, err error)
}

// SyncPeersResult is the agent-side shape of NodeService.SyncPeers response.
type SyncPeersResult struct {
	Version     string
	Peers       []PeerConfig
	NotModified bool
}

// ReportSessionStat is the agent-side telemetry shape (mirrors
// nodes.SessionStat in everything but package).
type ReportSessionStat struct {
	PeerPublicKey [32]byte
	LastHandshake time.Time
	RxBytes       int64
	TxBytes       int64
	EndpointMode  string
}

// AgentConfig configures the reconciler.
type AgentConfig struct {
	DeviceName   string // e.g. "wg0"
	PrivateKey   [32]byte
	ListenPort   int
	SyncInterval time.Duration // default 30s; overridable per-tick
	Engine       Engine
	Controller   ControllerClient
	Logger       *slog.Logger
}

// Agent is the long-running reconciler loop.
type Agent struct {
	cfg            AgentConfig
	logger         *slog.Logger
	currentVersion atomic.Value // string
	// metric counters (atomic so they can be inspected from tests).
	syncCount   atomic.Int64
	applyCount  atomic.Int64
	reportCount atomic.Int64
	syncErrors  atomic.Int64
}

// NewAgent constructs an Agent.
func NewAgent(cfg AgentConfig) (*Agent, error) {
	if cfg.SyncInterval == 0 {
		cfg.SyncInterval = 30 * time.Second
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	a := &Agent{cfg: cfg, logger: cfg.Logger}
	a.currentVersion.Store("")
	return a, nil
}

// Run blocks until ctx is cancelled, ticking every cfg.SyncInterval.
//
// We deliberately do NOT use a time.Ticker because that drifts on long
// pauses (e.g. when the host suspends). Sleeping between ticks gives us
// a more predictable cadence at the cost of slightly worse jitter, which
// doesn't matter for this workload.
func (a *Agent) Run(ctx context.Context) error {
	a.logger.Info("agent loop starting",
		"device", a.cfg.DeviceName,
		"interval", a.cfg.SyncInterval)
	for {
		a.reconcile(ctx)
		select {
		case <-ctx.Done():
			a.logger.Info("agent loop stopping", "reason", ctx.Err())
			return nil
		case <-time.After(a.cfg.SyncInterval):
		}
	}
}

// reconcile runs one tick of the sync→apply→report loop.
//
// Each step is wrapped in its own short-budget context derived from the
// loop ctx so a stuck call cannot delay the next tick indefinitely.
func (a *Agent) reconcile(ctx context.Context) {
	a.syncCount.Add(1)

	// Step 1: SyncPeers
	syncCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	current, _ := a.currentVersion.Load().(string)
	res, err := a.cfg.Controller.SyncPeers(syncCtx, current)
	if err != nil {
		a.syncErrors.Add(1)
		a.logger.Warn("SyncPeers failed", "err", err.Error())
		return
	}

	// Step 2: Apply if peer set changed
	if !res.NotModified {
		applyCtx, cancel2 := context.WithTimeout(ctx, 5*time.Second)
		err := a.cfg.Engine.Configure(applyCtx, a.cfg.DeviceName, DeviceConfig{
			PrivateKey:   a.cfg.PrivateKey,
			ListenPort:   a.cfg.ListenPort,
			Peers:        res.Peers,
			ReplacePeers: true,
		})
		cancel2()
		if err != nil {
			a.logger.Error("Engine.Configure failed", "err", err.Error())
			return
		}
		a.applyCount.Add(1)
		a.currentVersion.Store(res.Version)
		a.logger.Info("applied peer set",
			"version", res.Version,
			"peers", len(res.Peers))
	}

	// Step 3: Read device state and ReportSessions
	readCtx, cancel3 := context.WithTimeout(ctx, 5*time.Second)
	state, err := a.cfg.Engine.Read(readCtx, a.cfg.DeviceName)
	cancel3()
	if err != nil {
		a.logger.Warn("Engine.Read failed", "err", err.Error())
		return
	}

	if len(state.Peers) == 0 {
		return
	}

	stats := make([]ReportSessionStat, 0, len(state.Peers))
	for _, p := range state.Peers {
		// Only report peers that have completed at least one handshake;
		// peers that were just configured but haven't talked yet add noise.
		if p.LastHandshake.IsZero() {
			continue
		}
		stats = append(stats, ReportSessionStat{
			PeerPublicKey: p.PublicKey,
			LastHandshake: p.LastHandshake,
			RxBytes:       p.RxBytes,
			TxBytes:       p.TxBytes,
			// EndpointMode is hint-only; the agent doesn't always know
			// which mode the peer connected over.
		})
	}
	if len(stats) == 0 {
		return
	}

	reportCtx, cancel4 := context.WithTimeout(ctx, 10*time.Second)
	acc, rej, err := a.cfg.Controller.ReportSessions(reportCtx, stats)
	cancel4()
	if err != nil {
		a.logger.Warn("ReportSessions failed", "err", err.Error())
		return
	}
	a.reportCount.Add(1)
	if rej > 0 {
		a.logger.Info("session report had rejected peers",
			"accepted", acc, "rejected", rej)
	}
}

// CurrentVersion returns the peer-set version we most recently applied.
// Useful for /healthz endpoints.
func (a *Agent) CurrentVersion() string {
	v, _ := a.currentVersion.Load().(string)
	return v
}

// Stats returns counters useful for /metrics endpoints. The values are
// atomic snapshots so callers can call without blocking the loop.
type AgentStats struct {
	SyncCount   int64
	ApplyCount  int64
	ReportCount int64
	SyncErrors  int64
}

// Stats returns the current counters.
func (a *Agent) Stats() AgentStats {
	return AgentStats{
		SyncCount:   a.syncCount.Load(),
		ApplyCount:  a.applyCount.Load(),
		ReportCount: a.reportCount.Load(),
		SyncErrors:  a.syncErrors.Load(),
	}
}
