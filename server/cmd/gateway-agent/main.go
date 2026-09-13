// Command gateway-agent is the AidotVpn enforcement agent. It runs on the
// hospital-side gateway host, next to the kernel WireGuard interface.
//
// It does three things:
//
//  1. Polls the controller's authenticated GET /node/peers for the
//     desired peer list and each peer's destination ACL.
//  2. Applies that ACL as an nftables ruleset with a default-drop forward
//     chain — this is the authoritative access control, replacing the
//     blanket `iptables -A FORWARD -i wg0 -j ACCEPT` the dev compose
//     shipped with.
//  3. Optionally maintains an outbound WebSocket to a relay VPS so that
//     clients on LTE (carrier CGNAT) can reach this gateway without any
//     inbound firewall rule.
//
// It replaces infra/wireguard/reconcile-peers.sh, which polled an
// unauthenticated endpoint, ignored tenancy, and installed peers for
// devices that had not passed attestation.
//
// Requires: `wg` and `nft` on PATH, and CAP_NET_ADMIN.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/aidotvpn/server/internal/config"
	"github.com/aidotvpn/server/internal/gateway"
)

// agentVersion appears in the console's node list, so an operator can
// tell which build is running without shelling into the container.
//
// Set by the release script at build time; the fallback is what a
// locally built binary reports.
var agentVersion = "dev"

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "fatal: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	if envPath, count, err := config.LoadDotEnv(); err != nil {
		return fmt.Errorf("load .env: %w", err)
	} else if envPath != "" {
		fmt.Fprintf(os.Stderr, "loaded %d vars from %s\n", count, envPath)
	}

	var (
		controllerURL = flag.String("controller", envOr("CONTROLLER_URL", ""),
			"controller base URL, e.g. https://controller.hospital.local:10030")
		nodeToken = flag.String("node-token", envOr("NODE_TOKEN", ""),
			"per-node bearer token (issue with `migrate node-token -hostname ...`)")
		wgDevice = flag.String("device", envOr("WG_DEVICE", "wg0"),
			"WireGuard interface to manage")
		interval = flag.Duration("interval", envDuration("SYNC_INTERVAL", 15*time.Second),
			"how often to poll the controller")
		maxPolicyAge = flag.Duration("max-policy-age", envDuration("MAX_POLICY_AGE", 0), "readiness expires after this age")
		logDenied    = flag.Bool("log-denied", envBool("LOG_DENIED", true),
			"emit an nftables log line for packets the policy refuses")
		relayURL = flag.String("relay", envOr("RELAY_URL", ""),
			"relay base URL (e.g. wss://relay.example.com); empty disables the relay path")
		wgEndpoint = flag.String("wg-endpoint", envOr("WG_ENDPOINT", "127.0.0.1:52840"),
			"local WireGuard UDP listener the relay bridge injects into")
		healthAddr = flag.String("health-addr", envOr("HEALTH_ADDR", "127.0.0.1:10140"),
			"HTTP listen address for /healthz and /metrics")
		logLevel  = flag.String("log-level", envOr("LOG_LEVEL", "info"), "")
		logFormat = flag.String("log-format", envOr("LOG_FORMAT", "json"), "")
		oneshot   = flag.Bool("oneshot", false,
			"apply once and exit (useful for provisioning checks)")
		dryRun = flag.Bool("dry-run", false,
			"print the nftables ruleset that would be applied, then exit")
	)
	flag.Parse()
	if *maxPolicyAge <= 0 {
		*maxPolicyAge = 3 * *interval
		if *maxPolicyAge < 30*time.Second {
			*maxPolicyAge = 30 * time.Second
		}
	}

	logger := newLogger(*logLevel, *logFormat)
	slog.SetDefault(logger)

	if *controllerURL == "" {
		return errors.New("controller URL is required (-controller or CONTROLLER_URL)")
	}
	if *nodeToken == "" {
		return errors.New("node token is required (-node-token or NODE_TOKEN)")
	}

	// Fail fast on missing tooling. Discovering that `nft` is absent only
	// when the first policy arrives would leave the gateway forwarding
	// under whatever the host's default policy happens to be.
	if !*dryRun {
		if err := requireTools("wg", "nft"); err != nil {
			return err
		}
	}

	syncer := &gateway.Syncer{
		ControllerURL: *controllerURL,
		NodeToken:     *nodeToken,
		WGInterface:   *wgDevice,
		LogDenied:     *logDenied,
		Interval:      *interval,
		Logger:        logger,
	}

	if *dryRun {
		syncer.Runner = printRunner{out: os.Stdout}
		return syncer.SyncOnce(context.Background())
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if *oneshot {
		return syncer.SyncOnce(ctx)
	}

	logger.Info("aidotvpn gateway-agent starting",
		"controller", *controllerURL, "device", *wgDevice,
		"interval", *interval, "relay", relayState(*relayURL))

	// Relay bridge for clients that cannot reach us over UDP.
	if *relayURL != "" {
		rc := &gateway.RelayClient{
			RelayURL:      strings.TrimRight(*relayURL, "/"),
			ControllerURL: *controllerURL,
			NodeToken:     *nodeToken,
			WGEndpoint:    *wgEndpoint,
			Logger:        logger,
		}
		go func() {
			if err := rc.Run(ctx); err != nil && ctx.Err() == nil {
				logger.Error("relay client stopped", "err", err.Error())
			}
		}()
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) {
		// Readiness requires a recent successfully applied policy.
		if !syncer.Ready(time.Now(), *maxPolicyAge) {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte("policy missing or stale\n"))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ready\n"))
	})
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, _ *http.Request) {
		s := syncer.Stats()
		fmt.Fprintf(w, "aidotvpn_gateway_polls_total %d\n", s.Polls)
		fmt.Fprintf(w, "aidotvpn_gateway_poll_errors_total %d\n", s.PollErrors)
		fmt.Fprintf(w, "aidotvpn_gateway_rule_applies_total %d\n", s.RuleApplies)
		fmt.Fprintf(w, "aidotvpn_gateway_peer_applies_total %d\n", s.PeerApplies)
		fmt.Fprintf(w, "aidotvpn_gateway_apply_errors_total %d\n", s.ApplyErrors)
		fmt.Fprintf(w, "aidotvpn_gateway_peers %d\n", s.PeerCount)
		fmt.Fprintf(w, "aidotvpn_gateway_last_sync_unixtime %d\n", s.LastSyncUnix)
	})

	hsrv := &http.Server{
		Addr:              *healthAddr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		logger.Info("health server listening", "addr", *healthAddr)
		if err := hsrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("health server failed", "err", err.Error())
		}
	}()

	syncDone := make(chan struct{})
	go func() {
		_ = syncer.Run(ctx)
		close(syncDone)
	}()

	// Report what this gateway is actually running.
	//
	// 1.7.0 added reportLoop and never called it — so `nodes` kept the
	// seed row's empty columns, the console read 보고 없음, and
	// last_handshake_at was never written, which made every device show
	// 연결한 적 없음 no matter how much traffic it carried.
	//
	// Its own goroutine rather than folded into the syncer: a controller
	// that will not accept a report must not stop peers being applied.
	go reportLoop(ctx, &http.Client{Timeout: 10 * time.Second},
		*controllerURL, *nodeToken, *wgDevice, agentVersion, *interval)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	s := <-sig
	logger.Info("shutdown requested", "signal", s.String())

	cancel()
	shutdownCtx, sdc := context.WithTimeout(context.Background(), 10*time.Second)
	defer sdc()
	_ = hsrv.Shutdown(shutdownCtx)
	<-syncDone

	// Deliberately leave the nftables table in place on exit.
	//
	// Tearing it down would return the host to its default forward policy
	// — which on the dev compose image is ACCEPT — turning a routine
	// agent restart into a window of unrestricted access to the hospital
	// network. A stale-but-restrictive ruleset is the safer failure mode.
	logger.Info("gateway-agent stopped (nftables ruleset left in place)")
	return nil
}

// printRunner renders commands instead of executing them.
type printRunner struct{ out *os.File }

func (p printRunner) Run(_ context.Context, name string, args []string, stdin string) (string, error) {
	if name == "wg" && len(args) > 1 && args[0] == "show" {
		// Pretend the interface has no peers so the dry run shows the
		// full desired state rather than a diff against nothing.
		return "", nil
	}
	fmt.Fprintf(p.out, "\n$ %s %s\n", name, strings.Join(args, " "))
	if stdin != "" {
		fmt.Fprint(p.out, stdin)
	}
	return "", nil
}

func requireTools(names ...string) error {
	var missing []string
	for _, n := range names {
		if _, err := exec.LookPath(n); err != nil {
			missing = append(missing, n)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("required tool(s) not found on PATH: %s", strings.Join(missing, ", "))
	}
	return nil
}

func relayState(u string) string {
	if u == "" {
		return "disabled"
	}
	return u
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
