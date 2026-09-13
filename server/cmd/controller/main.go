// Command controller is the AidotVpn control server.
//
// At Phase 2a it provides:
//   - structured logging (slog)
//   - configuration loading
//   - DB connection pool with retry-on-startup
//   - automatic schema migration on boot
//   - /healthz, /readyz HTTP endpoints
//   - graceful shutdown on SIGINT/SIGTERM
//
// Subsequent phases will add OIDC, mTLS, and the gRPC services.
package main

import (
	"bufio"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"github.com/aidotvpn/server/internal/adminauth"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/aidotvpn/server/internal/allowlist"
	"github.com/aidotvpn/server/internal/attestation"
	"github.com/aidotvpn/server/internal/audit"
	"github.com/aidotvpn/server/internal/auth"
	"github.com/aidotvpn/server/internal/config"
	"github.com/aidotvpn/server/internal/db"
	"github.com/aidotvpn/server/internal/devices"
	"github.com/aidotvpn/server/internal/domain"
	"github.com/aidotvpn/server/internal/ha"
	"github.com/aidotvpn/server/internal/httpapi"
	"github.com/aidotvpn/server/internal/nodes"
	"github.com/aidotvpn/server/internal/playintegrity"
	"github.com/aidotvpn/server/internal/policies"
	"github.com/aidotvpn/server/internal/pqc"
	"github.com/aidotvpn/server/internal/users"
)

func main() {
	if err := run(); err != nil {
		// slog may not be wired up yet on early-fail; print plainly.
		fmt.Fprintf(os.Stderr, "fatal: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	// Load .env from cwd or any ancestor before reading config from env.
	// Variables already set in the process environment win, so this is safe
	// to call unconditionally — production deployments that inject secrets
	// via env or a secrets manager are unaffected.
	if envPath, count, err := config.LoadDotEnv(); err != nil {
		return fmt.Errorf("load .env: %w", err)
	} else if envPath != "" {
		fmt.Fprintf(os.Stderr, "loaded %d vars from %s\n", count, envPath)
	}

	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	logger := newLogger(cfg.LogLevel, cfg.LogFormat)
	slog.SetDefault(logger)
	logger.Info("aidotvpn controller starting",
		"http", cfg.HTTPListen,
		"grpc", cfg.GRPCListen,
		"db_host", cfg.DB.Host)

	// Connect to the DB and apply migrations.
	pool, err := db.Open(cfg.DB)
	if err != nil {
		return fmt.Errorf("db.Open: %w", err)
	}
	defer pool.Close()

	bootCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	if err := pool.PingWithRetry(bootCtx, 10, 500*time.Millisecond); err != nil {
		cancel()
		return fmt.Errorf("db unreachable: %w", err)
	}
	cancel()

	haGuard, err := ha.New(pool.DB, cfg.DB)
	if err != nil {
		return err
	}
	defer haGuard.Close()
	if haGuard.Enabled {
		if err := haGuard.CheckWriter(context.Background()); err != nil {
			return fmt.Errorf("HA startup: %w", err)
		}
	}

	migCtx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	v, err := db.MigrateUp(migCtx, cfg.DB)
	cancel()
	if err != nil {
		return fmt.Errorf("migrate: %w", err)
	}
	logger.Info("schema ready", "version", v)

	// Reconcile the dev-seeded node's public endpoint from environment.
	//
	// The schema seed (migration 0004) hardcodes the dev wg-data-node's
	// endpoint to "10.0.2.2:52840" — fine for emulator-on-host. For any
	// other deploy (LAN testing, production behind a public IP, customer
	// site with their own static IP), the operator sets:
	//
	//   AIDOTVPN_PUBLIC_ENDPOINT_HOST=vpn.acme.example.com
	//   AIDOTVPN_PUBLIC_ENDPOINT_PORT=52840
	//
	// and the controller updates node_endpoints accordingly on every
	// boot. This makes "deploy to a new customer site" a one-line .env
	// change instead of a DB migration. The host can be a hostname
	// (DDNS), an IPv4 (A record), or an IPv6 (AAAA) — the wg client
	// resolves it on every handshake initiation, so DDNS rotations are
	// picked up within ~5 minutes by all clients without code changes.
	if host := os.Getenv("AIDOTVPN_PUBLIC_ENDPOINT_HOST"); host != "" {
		port := getEnvUint16("AIDOTVPN_PUBLIC_ENDPOINT_PORT", 52840)
		if err := updateDevNodeEndpoint(context.Background(), pool.DB, host, port); err != nil {
			return fmt.Errorf("public endpoint reconcile: %w", err)
		}
		logger.Info("public endpoint reconciled", "host", host, "port", port)
	}

	// ----- Wire up services and admin REST API ------------------------------

	// Default tenant ID is seeded by migration 0001 to the well-known
	// UUIDv7 prefix below. All single-tenant deployments use this.
	defaultTenant, err := domain.ParseID("019650000000700080000000000000A1")
	if err != nil {
		return fmt.Errorf("parse default tenant id: %w", err)
	}

	// Console admins: argon2id + server sessions. Replaces the Keycloak
	// verifier (1.8.0). The first admin is created from
	// AIDOTVPN_ADMIN_EMAIL / AIDOTVPN_ADMIN_PASSWORD when the table is
	// empty, with must_change set so the seed password is used once.
	adminSvc := adminauth.New(pool.DB)
	// The account named in .env exists, whatever else does.
	//
	// 1.8.0 seeded it only when the table was empty. That left a machine
	// whose .env was written under an earlier default with only the old
	// account, and the new default in .env.example — which npm start
	// never copies over an existing value — unreachable. Ensure the
	// configured account is present instead: create it if missing,
	// leave it alone if it exists (its password may have been changed).
	if email, pw := os.Getenv("AIDOTVPN_ADMIN_EMAIL"), os.Getenv("AIDOTVPN_ADMIN_PASSWORD"); email != "" && pw != "" {
		exists, err := adminSvc.Exists(context.Background(), email)
		if err != nil {
			return fmt.Errorf("admin lookup: %w", err)
		}
		if !exists {
			if _, err := adminSvc.Create(context.Background(), defaultTenant, email, "관리자", pw, "admin", true); err != nil {
				return fmt.Errorf("seed admin: %w", err)
			}
			logger.Info("admin created from environment", "email", email)
		}
	} else if n, err := adminSvc.Count(context.Background()); err == nil && n == 0 {
		logger.Warn("no admins exist and AIDOTVPN_ADMIN_EMAIL/PASSWORD are unset — nobody can log in")
	}

	// Installed deployments load a persistent device CA; development keeps
	// the legacy ephemeral default only when no explicit env file is set.
	ca, err := auth.LoadConfiguredCA()
	if err != nil {
		return fmt.Errorf("ca: %w", err)
	}

	auditWriter := audit.New(pool.DB)
	usersRepo := users.New(pool.DB)

	devicesSvc, err := devices.New(devices.Config{
		DB:       pool.DB,
		CA:       ca,
		Audit:    auditWriter,
		TenantID: defaultTenant,
	})
	if err != nil {
		return fmt.Errorf("devices service: %w", err)
	}
	nodesSvc, err := nodes.New(nodes.Config{DB: pool.DB, Audit: auditWriter})
	if err != nil {
		return fmt.Errorf("nodes service: %w", err)
	}
	policiesSvc, err := policies.New(pool.DB, auditWriter)
	if err != nil {
		return fmt.Errorf("policies service: %w", err)
	}

	// ---- Hybrid post-quantum PSK (0.20.0) -------------------------------
	//
	// internal/pqc had complete, tested ML-KEM-768 primitives and no
	// caller since Phase 6, and tenant_kem_keys held nothing. Opt-in
	// rather than default-on: it is additive (the classical PSK remains
	// valid on its own) but it writes long-lived secret key material,
	// which a deployment should choose to hold rather than acquire by
	// upgrading.
	var kemStore *pqc.Store
	if os.Getenv("PQC_ENABLED") == "true" {
		kemStore = &pqc.Store{DB: pool.DB, Logger: logger}
		// Bounded: generating a keypair is sub-millisecond, so a hang
		// here means the database is unreachable and the controller
		// should say so rather than block startup indefinitely.
		kemCtx, cancelKem := context.WithTimeout(context.Background(), 15*time.Second)
		_, kerr := kemStore.EnsureKeypair(kemCtx, defaultTenant)
		cancelKem()
		if kerr != nil {
			return fmt.Errorf("tenant KEM keypair: %w", kerr)
		}
		devicesSvc.SetKEMStore(kemStore)
		logger.Info("hybrid post-quantum PSK enabled",
			"algorithm", pqc.AlgorithmMLKEM768,
			"note", "clients without ML-KEM support keep the classical PSK")
	}

	// ---- Hostname policy resolver (0.15.0) ------------------------------
	//
	// Resolves hostname-based policy rules and merges the answers into the
	// effective CIDR set. Without this goroutine running, a policy written
	// against hostnames resolves to nothing and — under deny-by-default —
	// the attached devices reach nothing.
	//
	// Wired here at the same time as the feature, deliberately. The last
	// three releases each shipped a mechanism whose connecting line was
	// missing; this one gets its startup log so an operator can see it is
	// alive.
	{
		res := &policies.Resolver{
			DB:     pool.DB,
			Logger: logger,
		}
		if d := os.Getenv("POLICY_RESOLVE_INTERVAL"); d != "" {
			if parsed, perr := time.ParseDuration(d); perr == nil {
				res.Interval = parsed
			} else {
				return fmt.Errorf("POLICY_RESOLVE_INTERVAL %q: %w", d, perr)
			}
		}
		if d := os.Getenv("POLICY_RESOLVE_GRACE"); d != "" {
			if parsed, perr := time.ParseDuration(d); perr == nil {
				res.Grace = parsed
			} else {
				return fmt.Errorf("POLICY_RESOLVE_GRACE %q: %w", d, perr)
			}
		}
		// Upstream selection, including optional DNS-over-TLS (0.25.0).
		//
		// Refuses to start when DoT is requested but misconfigured,
		// rather than falling back to cleartext: an operator who set
		// POLICY_RESOLVER_DOT=true and got plaintext anyway would be
		// worse off than one who never had the option.
		lookup, describe, rerr := policies.ResolverFromEnv()
		if rerr != nil {
			return fmt.Errorf("policy resolver: %w", rerr)
		}
		if lookup != nil {
			res.LookupIP = lookup
		}
		logger.Info("policy hostname resolver upstream", "upstream", describe)
		resolverCtx, stopResolver := context.WithCancel(context.Background())
		defer stopResolver()
		go res.Run(resolverCtx)
		logger.Info("policy hostname resolver started",
			"interval", orDefault(res.Interval, 5*time.Minute),
			"grace", orDefault(res.Grace, 30*time.Minute))
	}

	// ---- Hardware attestation (wired in 0.14.0) -------------------------
	//
	// 0.13.0 built the gate and never called this. Everything below the
	// config load existed already; the connection did not, so
	// ATTESTATION_MODE was an environment variable nothing read.
	attCfg, err := config.LoadAttestation()
	if err != nil {
		return fmt.Errorf("attestation config: %w", err)
	}
	if attCfg.Mode != "off" {
		var vopts []attestation.Option
		vopts = append(vopts,
			attestation.WithRequireVerifiedBoot(attCfg.RequireVerifiedBoot),
			attestation.WithMinSecurityLevel(attestation.SecurityLevel(attCfg.MinSecurityLevel)),
		)
		if attCfg.RootsPath != "" {
			rootPEM, rerr := os.ReadFile(attCfg.RootsPath)
			if rerr != nil {
				return fmt.Errorf("read attestation roots: %w", rerr)
			}
			vopts = append(vopts, attestation.WithRoots(rootPEM))
			logger.Info("attestation roots loaded", "path", attCfg.RootsPath)
		} else {
			// Only reachable in permissive mode — LoadAttestation refuses
			// enforce without roots. Every chain will fail path
			// validation, which is the point: the operator sees exactly
			// that in the logs instead of a quiet pass.
			logger.Warn("attestation enabled with NO trusted roots; " +
				"every chain will fail verification until ATTESTATION_ROOTS_PATH is set")
		}

		revoke := attestation.NewRevocation(logger)
		revoke.FailOpen = attCfg.RevocationFailOpen
		if attCfg.RevocationURL != "" {
			revoke.URL = attCfg.RevocationURL
		}
		// Runs for the process lifetime. Not tied to a request context:
		// the status list is process-global state, and cancelling it on
		// any one request finishing would leave the cache frozen.
		revokeCtx, stopRevoke := context.WithCancel(context.Background())
		defer stopRevoke()
		go revoke.Start(revokeCtx)
		vopts = append(vopts, attestation.WithRevocation(revoke))

		verifier := attestation.New(vopts...)

		allowSvc, aerr := allowlist.New(allowlist.Config{DB: pool.DB, Verifier: verifier})
		if aerr != nil {
			return fmt.Errorf("allowlist service: %w", aerr)
		}

		devicesSvc.SetAttestationGate(&devices.AttestationGate{
			Mode:             devices.AttestationMode(attCfg.Mode),
			Verifier:         verifier,
			Logger:           logger,
			ExpectedPackages: attCfg.ExpectedPackages,
			VerifyAndConsume: allowSvc.VerifyAndConsume,
		})
		// ---- Play Integrity (0.18.0) --------------------------------
		//
		// Wired here in the same commit as the decoder. internal/
		// playintegrity had a complete verdict policy and no way to
		// obtain a payload for eleven releases; adding the decoder
		// without this call would have left it exactly as unreachable.
		if pi := attCfg.PlayIntegrity; pi.Mode != "off" {
			sa, serr := playintegrity.LoadServiceAccount(pi.ServiceAccountPath)
			if serr != nil {
				return fmt.Errorf("play integrity service account: %w", serr)
			}
			decoder, derr := playintegrity.NewGoogleDecoder(sa, pi.PackageName)
			if derr != nil {
				return fmt.Errorf("play integrity decoder: %w", derr)
			}
			minLevel := playintegrity.IntegrityDevice
			switch pi.MinDeviceIntegrity {
			case "basic":
				minLevel = playintegrity.IntegrityBasic
			case "strong":
				minLevel = playintegrity.IntegrityStrong
			}
			piVerifier, verr := playintegrity.New(playintegrity.Config{
				Decoder:             decoder,
				ExpectedPackageName: pi.PackageName,
				MinDeviceIntegrity:  minLevel,
				AllowSideloaded:     pi.AllowSideloaded,
			})
			if verr != nil {
				return fmt.Errorf("play integrity verifier: %w", verr)
			}
			devicesSvc.SetPlayIntegrityGate(&devices.PlayIntegrityGate{
				Mode:                  devices.PlayIntegrityMode(pi.Mode),
				Verifier:              piVerifier,
				Logger:                logger,
				TreatWarningAsFailure: pi.TreatWarningAsFailure,
				NonceFor:              allowSvc.CurrentChallengeB64,
			})
			logger.Info("play integrity enabled",
				"mode", pi.Mode,
				"package", pi.PackageName,
				"min_device_integrity", pi.MinDeviceIntegrity,
				"allow_sideloaded", pi.AllowSideloaded,
				"warning_is_failure", pi.TreatWarningAsFailure)
		}

		logger.Info("attestation enabled",
			"mode", attCfg.Mode,
			"require_verified_boot", attCfg.RequireVerifiedBoot,
			"min_security_level", attCfg.MinSecurityLevel,
			"revocation_fail_open", attCfg.RevocationFailOpen,
			"expected_packages", len(attCfg.ExpectedPackages))
	} else {
		logger.Warn("attestation is OFF — any device can register")
	}

	// AIDOTVPN_ENABLE_DEV_ADMIN no longer gates an endpoint — /admin/dev/peers
	// was removed in 0.14.0. The variable is still read so that a compose
	// file or systemd unit that still sets it gets a clear migration
	// message instead of appearing to work.
	//
	// The startup refusal that used to live here (refuseDevAdminOnPublicListen)
	// is gone with it: there is no longer an unauthenticated surface to
	// guard against a public listen address.
	enableDevAdmin := os.Getenv("AIDOTVPN_ENABLE_DEV_ADMIN") == "true"
	if enableDevAdmin {
		logger.Warn("AIDOTVPN_ENABLE_DEV_ADMIN is set but has no effect since 0.14.0; " +
			"/admin/dev/peers was removed. Point the gateway at GET /node/peers " +
			"and issue it a token with `migrate node-token <hostname>`.")
	}

	api, err := httpapi.New(httpapi.Config{
		Admins:        adminSvc,
		Users:         usersRepo,
		Devices:       devicesSvc,
		Nodes:         nodesSvc,
		Audit:         auditWriter,
		Policies:      policiesSvc,
		KEM:           kemStore,
		DefaultTenant: defaultTenant,
		Logger:        logger,
		DB:            pool.DB,
		HAStatus:      haGuard.Status,
		// Dev admin endpoint — only on when explicitly opted in. The
		// docker-compose.yml sets this for the dev stack so the
		// wg-data-node sidecar can pull peer keys; production must NOT
		// set this var. We additionally refuse to boot above if it's
		// combined with a public listen address.
		EnableDevAdmin: enableDevAdmin,
		// Relay support (optional — leave both empty to disable).
		RelaySigningKey:   os.Getenv("RELAY_SIGNING_KEY"),
		RelaySharedSecret: os.Getenv("RELAY_SHARED_SECRET"),
	})
	if err != nil {
		return fmt.Errorf("httpapi: %w", err)
	}

	// readyz flips to true after migrations succeed; healthz is always true
	// once the process is up. Both are scraped by orchestrators.
	var ready atomic.Bool
	ready.Store(true)

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		if !ready.Load() || haGuard.CheckWriter(r.Context()) != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte("not ready\n"))
			return
		}
		// Database readiness is checked with a bounded two-second probe.
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ready\n"))
	})

	api.Register(mux)

	// We host /healthz and /readyz on the HTTP listen address. Phase 2c will
	// share the same listener with Connect handlers.
	srv := &http.Server{
		Addr:              cfg.HTTPListen,
		Handler:           haGuard.Wrap(mux),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       90 * time.Second,
	}

	// Run the server in a goroutine so we can listen for signals on the
	// main goroutine. ListenAndServe returns http.ErrServerClosed on
	// graceful shutdown — that's not an error.
	errCh := make(chan error, 1)
	go func() {
		logger.Info("http server listening", "addr", cfg.HTTPListen)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
		close(errCh)
	}()

	// Wait for either a signal or a server error.
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	serviceStop := make(chan struct{})
	if os.Getenv("AIDOTVPN_SERVICE_STDIN") == "1" {
		go func() {
			scanner := bufio.NewScanner(os.Stdin)
			for scanner.Scan() {
				if strings.TrimSpace(scanner.Text()) == "shutdown" {
					break
				}
			}
			close(serviceStop)
		}()
	}
	select {
	case <-serviceStop:
		logger.Info("service shutdown requested")
	case s := <-sig:
		logger.Info("shutdown requested", "signal", s.String())
	case err := <-errCh:
		if err != nil {
			return fmt.Errorf("http server: %w", err)
		}
		// Server exited cleanly on its own (unusual, but ok).
	}

	// Mark unready first so load balancers can drain.
	ready.Store(false)

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		logger.Error("http server shutdown", "err", err.Error())
	}
	logger.Info("aidotvpn controller stopped")
	return nil
}

// newLogger constructs the structured logger configured from CLI level/format.
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

	var h slog.Handler
	if format == "text" {
		h = slog.NewTextHandler(os.Stdout, opts)
	} else {
		h = slog.NewJSONHandler(os.Stdout, opts)
	}
	return slog.New(h)
}

// devLoopbackIssuerAliases returns a list of equivalent issuer URLs
// for the canonical one when both reference loopback / emulator-loopback
// hostnames. This lets a single Keycloak instance serve both:
//
//   - host PC clients (browser admin console at http://localhost:9110/...)
//   - Android emulator (host-loopback alias http://10.0.2.2:9110/...)
//
// Returns nil for any non-loopback issuer URL, so production calls are
// a no-op.
func devLoopbackIssuerAliases(issuer string) []string {
	// Pairings: each line is a pair of hostnames that mean "same Keycloak"
	// in dev. If the canonical issuer contains the LHS, we add an alias
	// with the RHS, and vice versa. Order in the slice is irrelevant —
	// the verifier accepts any match.
	pairs := [][2]string{
		{"localhost", "10.0.2.2"}, // Android Emulator
		{"127.0.0.1", "10.0.2.2"},
		{"localhost", "10.0.3.2"}, // Genymotion
		{"127.0.0.1", "10.0.3.2"},
	}
	var aliases []string
	for _, p := range pairs {
		if strings.Contains(issuer, p[0]) {
			aliases = append(aliases, strings.Replace(issuer, p[0], p[1], 1))
		}
		if strings.Contains(issuer, p[1]) {
			aliases = append(aliases, strings.Replace(issuer, p[1], p[0], 1))
		}
	}
	return aliases
}

// updateDevNodeEndpoint rewrites the dev-seeded node's endpoint host
// and port. Idempotent — re-running with the same values is a no-op
// at the SQL level (UPDATE matches 0 rows when nothing changed).
//
// We deliberately don't validate the host as a syntactically-correct
// hostname or IP because WireGuard's userspace will do its own
// resolution and surface clear errors if the value is bogus. Defending
// against operator typos at this layer would just add a parser without
// catching anything the client side won't catch better.
func updateDevNodeEndpoint(ctx context.Context, db *sql.DB, host string, port uint16) error {
	devEndpointID, err := domain.ParseID("019650000000700080000000000000B2")
	if err != nil {
		return err
	}
	res, err := db.ExecContext(ctx, `
		UPDATE node_endpoints
		   SET public_host = ?, public_port = ?
		 WHERE id = ?`,
		host, port, devEndpointID.Bytes())
	if err != nil {
		return fmt.Errorf("update dev endpoint: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		// Either the dev seed wasn't applied yet, or the row was
		// already at this value — both fine.
	}
	return nil
}

// getEnvUint16 reads a uint16 from environment, defaulting on missing
// or malformed values rather than failing boot. Public-facing port
// numbers are typically chosen at deploy time and rarely change, so
// silent default is friendlier than a fatal config error.
func getEnvUint16(key string, dflt uint16) uint16 {
	v := os.Getenv(key)
	if v == "" {
		return dflt
	}
	n, err := strconv.ParseUint(v, 10, 16)
	if err != nil {
		return dflt
	}
	return uint16(n)
}

// orDefault reports d, or def when d is zero. Used only for the startup
// log line, so that it shows the value the resolver will actually apply
// rather than an empty duration.
func orDefault(d, def time.Duration) time.Duration {
	if d <= 0 {
		return def
	}
	return d
}
