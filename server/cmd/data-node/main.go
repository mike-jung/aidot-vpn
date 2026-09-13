// Command data-node is the AidotVpn WireGuard data-plane agent.
//
// It runs alongside the kernel WG interface on each gateway host. On a
// timer it pulls the authoritative peer list from the controller, applies
// it via the Engine abstraction (wgctrl-go in production; an in-memory
// implementation for testing), and reports session telemetry back.
//
// In Phase 3 the agent ships with a minimal, in-memory Engine so the
// binary builds and runs end-to-end without root or a kernel WG module.
// Production deployments swap that out for the wgctrl-go-backed engine —
// see docs/dataplane-wgctrl.md for the adapter implementation.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/aidotvpn/server/internal/config"
	"github.com/aidotvpn/server/internal/dataplane"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "fatal: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	// Load .env before reading any environment-default flags below.
	if envPath, count, err := config.LoadDotEnv(); err != nil {
		return fmt.Errorf("load .env: %w", err)
	} else if envPath != "" {
		fmt.Fprintf(os.Stderr, "loaded %d vars from %s\n", count, envPath)
	}

	cfg := struct {
		controllerURL string
		nodeCertPath  string
		nodeKeyPath   string
		caCertPath    string
		device        string
		listenPort    int
		syncInterval  time.Duration
		healthAddr    string
		logLevel      string
		logFormat     string
		fakeEngine    bool
	}{}
	flag.StringVar(&cfg.controllerURL, "controller", envOr("CONTROLLER_URL", ""),
		"AidotVpn controller URL, e.g. https://controller.example.com:10021")
	flag.StringVar(&cfg.nodeCertPath, "node-cert", envOr("NODE_CERT", ""),
		"path to the node's mTLS client certificate (PEM)")
	flag.StringVar(&cfg.nodeKeyPath, "node-key", envOr("NODE_KEY", ""),
		"path to the node's mTLS client key (PEM)")
	flag.StringVar(&cfg.caCertPath, "ca-cert", envOr("CA_CERT", ""),
		"path to the controller's CA certificate (PEM, for cert pinning)")
	flag.StringVar(&cfg.device, "device", envOr("WG_DEVICE", "wg0"),
		"WireGuard device name to manage")
	flag.IntVar(&cfg.listenPort, "listen-port", envInt("WG_LISTEN_PORT", 52840),
		"WireGuard UDP listen port")
	flag.DurationVar(&cfg.syncInterval, "sync-interval",
		envDuration("SYNC_INTERVAL", 30*time.Second),
		"how often to call NodeService.SyncPeers")
	flag.StringVar(&cfg.healthAddr, "health-addr", envOr("HEALTH_ADDR", "127.0.0.1:9110"),
		"HTTP listen address for /healthz and /metrics")
	flag.StringVar(&cfg.logLevel, "log-level", envOr("LOG_LEVEL", "info"), "")
	flag.StringVar(&cfg.logFormat, "log-format", envOr("LOG_FORMAT", "json"), "")
	flag.BoolVar(&cfg.fakeEngine, "fake-engine",
		envBool("FAKE_ENGINE", true),
		"use the in-memory Engine instead of wgctrl-go (true in dev)")
	flag.Parse()

	logger := newLogger(cfg.logLevel, cfg.logFormat)
	slog.SetDefault(logger)

	logger.Info("aidotvpn data-node starting",
		"controller", cfg.controllerURL,
		"device", cfg.device,
		"listen_port", cfg.listenPort,
		"sync_interval", cfg.syncInterval,
		"fake_engine", cfg.fakeEngine)

	// Engine selection.
	var engine dataplane.Engine
	if cfg.fakeEngine {
		engine = dataplane.NewMemoryEngine()
	} else {
		// Production: build with `--tags wgctrl` and link in the wgctrl-go-
		// backed engine. See docs/dataplane-wgctrl.md.
		return errors.New("wgctrl engine not built into this binary; pass -fake-engine to run in dev mode, or build with the wgctrl build tag")
	}
	defer engine.Close()

	// ControllerClient is created once, holds open the gRPC connection.
	// In Phase 3a this is a stub that fails every call; once the user
	// runs `buf generate` the real Connect-go-backed client takes over —
	// see docs/dataplane-controller-client.md.
	controller := stubControllerClient{logger: logger}

	// Build the agent.
	priv, err := loadPrivateKey(cfg)
	if err != nil {
		return fmt.Errorf("load private key: %w", err)
	}

	agent, err := dataplane.NewAgent(dataplane.AgentConfig{
		DeviceName:   cfg.device,
		PrivateKey:   priv,
		ListenPort:   cfg.listenPort,
		SyncInterval: cfg.syncInterval,
		Engine:       engine,
		Controller:   controller,
		Logger:       logger,
	})
	if err != nil {
		return fmt.Errorf("new agent: %w", err)
	}

	// Health server.
	var ready atomic.Bool
	ready.Store(true)
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) {
		if !ready.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ready\n"))
	})
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, _ *http.Request) {
		s := agent.Stats()
		fmt.Fprintf(w, "aidotvpn_dataplane_sync_total %d\n", s.SyncCount)
		fmt.Fprintf(w, "aidotvpn_dataplane_apply_total %d\n", s.ApplyCount)
		fmt.Fprintf(w, "aidotvpn_dataplane_report_total %d\n", s.ReportCount)
		fmt.Fprintf(w, "aidotvpn_dataplane_sync_errors_total %d\n", s.SyncErrors)
		fmt.Fprintf(w, "aidotvpn_dataplane_current_version{version=\"%s\"} 1\n", agent.CurrentVersion())
	})

	hsrv := &http.Server{
		Addr:              cfg.healthAddr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	httpErr := make(chan error, 1)
	go func() {
		logger.Info("health server listening", "addr", cfg.healthAddr)
		if err := hsrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			httpErr <- err
		}
		close(httpErr)
	}()

	// Run the agent until SIGTERM.
	agentDone := make(chan struct{})
	go func() {
		_ = agent.Run(ctx)
		close(agentDone)
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	select {
	case s := <-sig:
		logger.Info("shutdown requested", "signal", s.String())
	case err := <-httpErr:
		if err != nil {
			cancel()
			return fmt.Errorf("health server: %w", err)
		}
	}

	ready.Store(false)
	cancel()

	// Drain.
	shutdownCtx, sdc := context.WithTimeout(context.Background(), 10*time.Second)
	defer sdc()
	_ = hsrv.Shutdown(shutdownCtx)
	<-agentDone

	logger.Info("aidotvpn data-node stopped")
	return nil
}

// stubControllerClient is wired in until `buf generate` produces the
// real Connect-go-backed client. It returns an error from every call so
// the agent's loop exercises its error paths in dev. Replace its body
// with the real client per docs/dataplane-controller-client.md.
type stubControllerClient struct {
	logger *slog.Logger
}

func (s stubControllerClient) SyncPeers(ctx context.Context, _ string) (*dataplane.SyncPeersResult, error) {
	return nil, errors.New("controller client not yet wired (run `buf generate`)")
}

func (s stubControllerClient) ReportSessions(ctx context.Context, _ []dataplane.ReportSessionStat) (uint32, uint32, error) {
	return 0, 0, errors.New("controller client not yet wired (run `buf generate`)")
}

// loadPrivateKey loads the device's WG private key. For dev with the
// fake engine, we use a fixed all-zeros key. Production loads from a
// pre-provisioned file (NODE_WG_KEY_PATH).
func loadPrivateKey(cfg struct {
	controllerURL string
	nodeCertPath  string
	nodeKeyPath   string
	caCertPath    string
	device        string
	listenPort    int
	syncInterval  time.Duration
	healthAddr    string
	logLevel      string
	logFormat     string
	fakeEngine    bool
}) ([32]byte, error) {
	// Phase 3a: zero key in dev. Phase 3b will replace this with file
	// loading from NODE_WG_KEY_PATH.
	var k [32]byte
	return k, nil
}

func newLogger(level, format string) *slog.Logger {
	var lvl slog.Level
	switch strings.ToLower(level) {
	case "debug":
		lvl = slog.LevelDebug
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}
	opts := &slog.HandlerOptions{Level: lvl}
	if format == "text" {
		return slog.New(slog.NewTextHandler(os.Stdout, opts))
	}
	return slog.New(slog.NewJSONHandler(os.Stdout, opts))
}

func envOr(key, def string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return def
}

func envInt(key string, def int) int {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		return def
	}
	var n int
	_, err := fmt.Sscanf(v, "%d", &n)
	if err != nil {
		return def
	}
	return n
}

func envDuration(key string, def time.Duration) time.Duration {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return def
	}
	return d
}

func envBool(key string, def bool) bool {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		return def
	}
	switch strings.ToLower(v) {
	case "1", "true", "yes":
		return true
	case "0", "false", "no":
		return false
	default:
		return def
	}
}
