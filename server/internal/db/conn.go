// Package db owns the MariaDB connection pool and migrations runner for the
// AidotVpn controller.
//
// Design notes:
//
//  1. We use the standard database/sql package with go-sql-driver/mysql.
//     There is no ORM. Repository code lives next to its domain package
//     and uses sqlx-style scanning helpers when convenient.
//
//  2. The pool is opened lazily; Open() validates the DSN syntactically but
//     does NOT block on a connection. Use Ping(ctx) for that.
//
//  3. Migrations are embedded into the binary so a single artifact carries
//     everything it needs. See migrate.go.
package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	_ "github.com/go-sql-driver/mysql" // registers the "mysql" driver

	"github.com/aidotvpn/server/internal/config"
)

// ErrNotFound is returned by repositories when a single-row lookup misses.
// Wrapping sql.ErrNoRows lets callers check with errors.Is.
var ErrNotFound = errors.New("aidotvpn: record not found")

// DB wraps *sql.DB so we can attach helpers without exposing the underlying
// type to repository code. Embedding *sql.DB keeps the standard API
// available through the wrapper.
type DB struct {
	*sql.DB
	cfg config.DBConfig
}

// Open creates a new connection pool from the given config. The returned DB
// is safe for concurrent use.
//
// Open does NOT verify connectivity — call Ping(ctx) for that. We split the
// two so callers (e.g. the migration CLI) can apply timeouts of their own.
func Open(cfg config.DBConfig) (*DB, error) {
	dsn := cfg.DSN()
	pool, err := sql.Open("mysql", dsn)
	if err != nil {
		return nil, fmt.Errorf("db.Open: %w", err)
	}

	pool.SetMaxOpenConns(cfg.MaxOpenConns)
	pool.SetMaxIdleConns(cfg.MaxIdleConns)
	pool.SetConnMaxLifetime(cfg.ConnMaxLife)
	// Idle conns are recycled aggressively so we don't pin to a stale TCP
	// session after a database restart.
	pool.SetConnMaxIdleTime(5 * time.Minute)

	return &DB{DB: pool, cfg: cfg}, nil
}

// PingWithRetry tries to open a connection up to attempts times with
// exponential backoff. Useful at process start when the database is in the
// same docker-compose project and may still be initialising.
func (d *DB) PingWithRetry(ctx context.Context, attempts int, baseDelay time.Duration) error {
	var lastErr error
	delay := baseDelay
	for i := 0; i < attempts; i++ {
		// Per-attempt timeout; total budget is bounded by the parent ctx too.
		attemptCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		err := d.PingContext(attemptCtx)
		cancel()
		if err == nil {
			return nil
		}
		lastErr = err
		select {
		case <-ctx.Done():
			return fmt.Errorf("ping cancelled: %w (last err: %v)", ctx.Err(), lastErr)
		case <-time.After(delay):
		}
		// Exponential backoff capped at 5s
		delay *= 2
		if delay > 5*time.Second {
			delay = 5 * time.Second
		}
	}
	return fmt.Errorf("db ping failed after %d attempts: %w", attempts, lastErr)
}

// Tx runs fn inside a transaction. If fn returns an error, the transaction
// is rolled back; otherwise it is committed. Rollback errors are joined
// (via errors.Join) so the caller gets the full picture.
//
// We deliberately use sql.LevelReadCommitted as the default isolation level.
// MariaDB's REPEATABLE READ default can produce surprises on long-running
// reports; READ COMMITTED matches most tools' expectations.
func (d *DB) Tx(ctx context.Context, fn func(*sql.Tx) error) error {
	tx, err := d.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return fmt.Errorf("BeginTx: %w", err)
	}
	defer func() {
		// In case of a panic, ensure rollback runs.
		if p := recover(); p != nil {
			_ = tx.Rollback()
			panic(p)
		}
	}()

	if err := fn(tx); err != nil {
		if rbErr := tx.Rollback(); rbErr != nil && !errors.Is(rbErr, sql.ErrTxDone) {
			return errors.Join(err, fmt.Errorf("rollback: %w", rbErr))
		}
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit: %w", err)
	}
	return nil
}
