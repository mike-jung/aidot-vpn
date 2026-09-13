// cmd/relay is the cloud-resident WebSocket relay. Deploy it to a small
// VPS with a public IP and put a TLS-terminating reverse proxy
// (Caddy/nginx) in front. The relay process itself speaks plain HTTP/WS
// — TLS lives at the proxy.
//
// Required environment:
//
//	RELAY_LISTEN              addr:port to bind, e.g. 0.0.0.0:8080
//	RELAY_CONTROLLER_URL      base URL of the controller relay-auth API
//	RELAY_SHARED_SECRET       value the controller expects in
//	                           X-Relay-Secret header
//
// Optional:
//
//	RELAY_LOG_LEVEL           debug|info|warn|error  (default info)
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/aidotvpn/server/internal/relay"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: parseLevel(os.Getenv("RELAY_LOG_LEVEL")),
	}))

	listen := envOr("RELAY_LISTEN", "0.0.0.0:8080")
	ctrlURL := os.Getenv("RELAY_CONTROLLER_URL")
	secret := os.Getenv("RELAY_SHARED_SECRET")
	if ctrlURL == "" || secret == "" {
		logger.Error("RELAY_CONTROLLER_URL and RELAY_SHARED_SECRET are required")
		os.Exit(2)
	}

	auth := relay.NewHTTPAuth(ctrlURL, secret)
	hub := relay.NewHub(auth, logger)

	srv := &http.Server{
		Addr:              listen,
		Handler:           hub,
		ReadHeaderTimeout: 5 * time.Second,
		// No ReadTimeout: WebSocket connections are long-lived. Per-frame
		// deadlines are managed inside relay.conn.
		WriteTimeout: 0,
		IdleTimeout:  0,
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	go func() {
		logger.Info("relay listening", "addr", listen, "controller", ctrlURL)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("listen failed", "err", err.Error())
			os.Exit(1)
		}
	}()

	<-ctx.Done()
	logger.Info("shutdown requested")
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		logger.Warn("graceful shutdown failed", "err", err.Error())
	}
}

func envOr(k, dflt string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return dflt
}

func parseLevel(s string) slog.Level {
	switch s {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
