// Command migrate applies database migrations for the AidotVpn controller.
//
// Usage:
//
//	migrate up                      # apply all pending migrations
//	migrate down [N]                # roll back N migrations (default 1)
//	migrate version                 # print current version + dirty flag
//
// Configuration is read from environment variables (see internal/config).
package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/aidotvpn/server/internal/config"
	"github.com/aidotvpn/server/internal/db"
	"github.com/aidotvpn/server/internal/httpapi"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	if len(os.Args) < 2 {
		return usage()
	}

	if envPath, count, err := config.LoadDotEnv(); err != nil {
		return fmt.Errorf("load .env: %w", err)
	} else if envPath != "" {
		fmt.Fprintf(os.Stderr, "loaded %d vars from %s\n", count, envPath)
	}

	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	switch os.Args[1] {
	case "up":
		v, err := db.MigrateUp(ctx, cfg.DB)
		if err != nil {
			return err
		}
		fmt.Printf("schema is now at version %d\n", v)
		return nil

	case "down":
		steps := 1
		if len(os.Args) >= 3 {
			n, perr := strconv.Atoi(os.Args[2])
			if perr != nil || n < 0 {
				return fmt.Errorf("down: %q is not a non-negative integer", os.Args[2])
			}
			steps = n
		}
		if err := db.MigrateDown(ctx, cfg.DB, steps); err != nil {
			return err
		}
		fmt.Printf("rolled back %d step(s)\n", steps)
		return nil

	case "version":
		v, dirty, err := db.MigrateVersion(ctx, cfg.DB)
		if err != nil {
			return err
		}
		fmt.Printf("version=%d dirty=%v\n", v, dirty)
		return nil

	case "node-endpoint":
		// Point the seeded node at where the gateway actually is.
		//
		//   migrate node-endpoint <hostname> <host> <port>
		//
		// Migration 0004 seeds 10.0.2.2:51820 — the Android emulator's
		// alias for its host. A real handset sending a handshake there
		// is sending it nowhere, and WireGuard says nothing about an
		// absent peer: the phone logged "Sending handshake initiation"
		// twelve times with no answer, and the app read 연결됨 because
		// its own interface was up.
		//
		// npm start calls this with the machine's LAN address and the
		// configured port, so a moved server is followed automatically.
		if len(os.Args) < 5 {
			return errors.New("node-endpoint: usage is `migrate node-endpoint <hostname> <host> <port>`")
		}
		hostname, host, portStr := os.Args[2], os.Args[3], os.Args[4]
		port, err := strconv.Atoi(portStr)
		if err != nil || port < 1 || port > 65535 {
			return fmt.Errorf("node-endpoint: bad port %q", portStr)
		}

		conn, err := db.Open(cfg.DB)
		if err != nil {
			return fmt.Errorf("open db: %w", err)
		}
		defer conn.Close()

		res, err := conn.ExecContext(ctx, `
			UPDATE node_endpoints e
			  JOIN nodes n ON n.id = e.node_id
			   SET e.public_host = ?, e.public_port = ?
			 WHERE n.hostname = ? AND e.mode = 'wg'`, host, port, hostname)
		if err != nil {
			return fmt.Errorf("node-endpoint: %w", err)
		}
		if n, _ := res.RowsAffected(); n == 0 {
			// Zero rows is either "no such node" or "already this value".
			// Check which, so the operator is not told a node is missing
			// when the address simply did not change.
			var count int
			_ = conn.QueryRowContext(ctx, `
				SELECT COUNT(*) FROM node_endpoints e JOIN nodes n ON n.id = e.node_id
				 WHERE n.hostname = ? AND e.mode = 'wg'`, hostname).Scan(&count)
			if count == 0 {
				return fmt.Errorf("node-endpoint: no wg endpoint for node %q", hostname)
			}
		}
		fmt.Printf("node:     %s\nendpoint: %s:%d\n", hostname, host, port)
		return nil

	case "node-token":
		// Provision a gateway agent credential.
		//
		//   migrate node-token <hostname>
		//
		// Prints the token exactly once. Only its SHA-256 is stored, so
		// there is no way to recover it later — re-run to rotate, which
		// invalidates the previous token immediately.
		if len(os.Args) < 3 {
			return errors.New("node-token: usage is `migrate node-token <hostname>`")
		}
		hostname := os.Args[2]

		conn, err := db.Open(cfg.DB)
		if err != nil {
			return fmt.Errorf("open db: %w", err)
		}
		defer conn.Close()
		if err := conn.PingWithRetry(ctx, 3, 500*time.Millisecond); err != nil {
			return fmt.Errorf("ping db: %w", err)
		}

		// 32 bytes of CSPRNG output, base64url. Long enough that an
		// online guessing attack against /node/peers is hopeless, short
		// enough to paste into a systemd env file without wrapping.
		buf := make([]byte, 32)
		if _, err := rand.Read(buf); err != nil {
			return fmt.Errorf("generate token: %w", err)
		}
		token := base64.RawURLEncoding.EncodeToString(buf)

		if err := httpapi.SetNodeAgentToken(ctx, conn.DB, hostname, token); err != nil {
			if errors.Is(err, httpapi.ErrNodeNotFound) {
				return fmt.Errorf("no node with hostname %q "+
					"(check `SELECT hostname FROM nodes`)", hostname)
			}
			return err
		}

		fmt.Printf("node:     %s\n", hostname)
		fmt.Printf("token:    %s\n\n", token)
		fmt.Fprintln(os.Stderr,
			"Store this in the gateway host's /etc/aidotvpn/agent.env as NODE_TOKEN=.\n"+
				"It is shown once and cannot be recovered — re-run this command to rotate.")
		return nil

	case "-h", "--help", "help":
		return usage()

	default:
		return errors.New("unknown subcommand: " + os.Args[1] + " (try 'help')")
	}
}

func usage() error {
	fmt.Fprintln(os.Stderr, `aidotvpn migrate

USAGE
  migrate up               apply all pending migrations
  migrate down [N]         roll back N migrations (default 1; 0 = all)
  migrate version          print the current schema version and dirty flag
  migrate node-token HOST  issue a gateway agent token for node HOST (shown once)

ENVIRONMENT
  AIDOTVPN_DB_HOST         (default 127.0.0.1)
  AIDOTVPN_DB_PORT         (default 4336)
  AIDOTVPN_DB_USER         (required)
  AIDOTVPN_DB_PASSWORD     (required)
  AIDOTVPN_DB_NAME         (default aidotvpn)
  AIDOTVPN_DB_TLS          (default preferred)`)
	return nil
}
