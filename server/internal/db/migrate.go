// Migration runner for the AidotVpn controller.
//
// We deliberately keep this dependency-free (stdlib + the MySQL driver only).
// The migration table is named `schema_migrations` and uses the same
// (version, dirty) shape as golang-migrate so we can switch later without
// data conversion if we ever need to.
//
// Behaviour:
//
//   - Migrations live in internal/db/migrations/<NNNN>_<name>.{up|down}.sql.
//   - On Up(): for each version above the current applied version, in order,
//     mark the version as dirty, run the SQL, then clear dirty + record.
//   - On Down(steps): run the .down.sql for the current version, decrement,
//     repeat steps times.
//   - If the table reports dirty=true at startup, refuse to run further
//     migrations until an operator intervenes (this matches golang-migrate).
//
// MariaDB caveats:
//
//   - Most DDL statements implicitly commit. We therefore execute each
//     migration's body OUTSIDE a transaction; the dirty flag is the safety
//     net for partial failures.
//   - Multi-statement scripts: we split on `;` followed by newline at the
//     top level. This is enough for our hand-written, well-formed migrations
//     that never put `;\n` inside string literals or stored programs. For
//     anything more complex, write one statement per file.
package db

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/aidotvpn/server/internal/config"
)

// Embedded migrations (filenames like 0001_init.up.sql / 0001_init.down.sql).
//
//go:embed migrations/*.sql
var migrationsFS embed.FS

// ErrDirty is returned when the schema_migrations table reports that the
// last migration attempt did not complete cleanly. Operators must inspect
// the database, fix any partial state, and clear the dirty flag manually
// before further migrations can be applied.
var ErrDirty = errors.New("schema_migrations is dirty; manual intervention required")

// migrationFileRE matches NNNN_<anything>.up.sql or .down.sql .
var migrationFileRE = regexp.MustCompile(`^(\d{4})_([A-Za-z0-9_-]+)\.(up|down)\.sql$`)

// migration represents one ordered version with both directions resolved.
type migration struct {
	version uint
	name    string
	up      string // SQL contents (may be empty if file missing)
	down    string
}

// loadMigrations reads and groups all embedded migration files by version.
func loadMigrations() ([]migration, error) {
	entries, err := fs.ReadDir(migrationsFS, "migrations")
	if err != nil {
		return nil, fmt.Errorf("read migrations dir: %w", err)
	}

	byVersion := map[uint]*migration{}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		// Skip the README and other non-SQL files.
		if !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		m := migrationFileRE.FindStringSubmatch(e.Name())
		if m == nil {
			return nil, fmt.Errorf("unexpected SQL file in migrations dir: %s", e.Name())
		}
		ver, _ := strconv.ParseUint(m[1], 10, 32)
		name := m[2]
		dir := m[3]

		body, err := fs.ReadFile(migrationsFS, path.Join("migrations", e.Name()))
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", e.Name(), err)
		}
		entry := byVersion[uint(ver)]
		if entry == nil {
			entry = &migration{version: uint(ver), name: name}
			byVersion[uint(ver)] = entry
		}
		if entry.name != name {
			return nil, fmt.Errorf("version %d name mismatch: %q vs %q",
				ver, entry.name, name)
		}
		switch dir {
		case "up":
			entry.up = string(body)
		case "down":
			entry.down = string(body)
		}
	}

	out := make([]migration, 0, len(byVersion))
	for _, m := range byVersion {
		if m.up == "" {
			return nil, fmt.Errorf("version %d (%s) has no .up.sql", m.version, m.name)
		}
		if m.down == "" {
			return nil, fmt.Errorf("version %d (%s) has no .down.sql", m.version, m.name)
		}
		out = append(out, *m)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].version < out[j].version })
	return out, nil
}

// ensureMigrationsTable creates `schema_migrations` if it does not exist.
// Schema mirrors golang-migrate's MySQL implementation for forward compat.
func ensureMigrationsTable(ctx context.Context, conn *sql.DB) error {
	_, err := conn.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version BIGINT NOT NULL PRIMARY KEY,
			dirty   BOOLEAN NOT NULL
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`)
	if err != nil {
		return fmt.Errorf("create schema_migrations: %w", err)
	}
	return nil
}

// readVersion returns the currently-applied version and dirty flag.
// version=0 means no migrations applied yet.
func readVersion(ctx context.Context, conn *sql.DB) (uint, bool, error) {
	row := conn.QueryRowContext(ctx,
		`SELECT version, dirty FROM schema_migrations LIMIT 1`)
	var v uint
	var d bool
	switch err := row.Scan(&v, &d); err {
	case nil:
		return v, d, nil
	case sql.ErrNoRows:
		return 0, false, nil
	default:
		return 0, false, fmt.Errorf("read version: %w", err)
	}
}

// writeVersion replaces the single row in schema_migrations.
func writeVersion(ctx context.Context, conn *sql.DB, v uint, dirty bool) error {
	_, err := conn.ExecContext(ctx, `DELETE FROM schema_migrations`)
	if err != nil {
		return fmt.Errorf("clear schema_migrations: %w", err)
	}
	if v == 0 && !dirty {
		// Fully reverted state — leave the table empty.
		return nil
	}
	_, err = conn.ExecContext(ctx,
		`INSERT INTO schema_migrations (version, dirty) VALUES (?, ?)`,
		v, dirty)
	if err != nil {
		return fmt.Errorf("write schema_migrations: %w", err)
	}
	return nil
}

// splitStatements separates a migration body into individual statements.
// We split on `;` ignoring whitespace, after stripping `--` line comments.
// This is sufficient for our hand-written migrations.
func splitStatements(body string) []string {
	// Strip line comments first to avoid `;` inside `-- ...`.
	lines := strings.Split(body, "\n")
	for i, ln := range lines {
		if idx := strings.Index(ln, "--"); idx >= 0 {
			lines[i] = ln[:idx]
		}
	}
	clean := strings.Join(lines, "\n")

	parts := strings.Split(clean, ";")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		s := strings.TrimSpace(p)
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

// applyOne runs a single migration body. Statements are executed
// sequentially; we don't open a transaction because most DDL implicitly
// commits in MariaDB anyway.
func applyOne(ctx context.Context, conn *sql.DB, body string) error {
	for _, stmt := range splitStatements(body) {
		if _, err := conn.ExecContext(ctx, stmt); err != nil {
			// Truncate the SQL in error messages so we don't dump the whole
			// migration into the log.
			snip := stmt
			if len(snip) > 200 {
				snip = snip[:200] + "..."
			}
			return fmt.Errorf("statement failed: %w\n--- sql ---\n%s\n----------", err, snip)
		}
	}
	return nil
}

// MigrateUp applies all pending migrations and returns the new version.
func MigrateUp(ctx context.Context, cfg config.DBConfig) (uint, error) {
	pool, err := Open(cfg)
	if err != nil {
		return 0, err
	}
	defer pool.Close()
	if err := ensureMigrationsTable(ctx, pool.DB); err != nil {
		return 0, err
	}
	cur, dirty, err := readVersion(ctx, pool.DB)
	if err != nil {
		return 0, err
	}
	if dirty {
		return cur, fmt.Errorf("%w (current version %d)", ErrDirty, cur)
	}

	migs, err := loadMigrations()
	if err != nil {
		return cur, err
	}

	for _, m := range migs {
		if m.version <= cur {
			continue
		}
		// Mark dirty before applying so a crash leaves a visible breadcrumb.
		if err := writeVersion(ctx, pool.DB, m.version, true); err != nil {
			return cur, err
		}
		if err := applyOne(ctx, pool.DB, m.up); err != nil {
			return cur, fmt.Errorf("migration %04d_%s.up: %w", m.version, m.name, err)
		}
		if err := writeVersion(ctx, pool.DB, m.version, false); err != nil {
			return cur, err
		}
		cur = m.version
	}
	return cur, nil
}

// MigrateDown rolls back `steps` migrations. steps==0 means "all the way".
func MigrateDown(ctx context.Context, cfg config.DBConfig, steps int) error {
	pool, err := Open(cfg)
	if err != nil {
		return err
	}
	defer pool.Close()
	if err := ensureMigrationsTable(ctx, pool.DB); err != nil {
		return err
	}
	cur, dirty, err := readVersion(ctx, pool.DB)
	if err != nil {
		return err
	}
	if dirty {
		return fmt.Errorf("%w (current version %d)", ErrDirty, cur)
	}
	if cur == 0 {
		return nil
	}

	migs, err := loadMigrations()
	if err != nil {
		return err
	}

	// Walk backwards through versions <= cur.
	rev := make([]migration, 0, len(migs))
	for i := len(migs) - 1; i >= 0; i-- {
		if migs[i].version <= cur {
			rev = append(rev, migs[i])
		}
	}
	if steps <= 0 {
		steps = len(rev)
	}
	for i := 0; i < steps && i < len(rev); i++ {
		m := rev[i]
		if err := writeVersion(ctx, pool.DB, m.version, true); err != nil {
			return err
		}
		if err := applyOne(ctx, pool.DB, m.down); err != nil {
			return fmt.Errorf("migration %04d_%s.down: %w", m.version, m.name, err)
		}
		// Find the previous version (one before m.version), if any.
		var prev uint
		for j := len(migs) - 1; j >= 0; j-- {
			if migs[j].version < m.version {
				prev = migs[j].version
				break
			}
		}
		if err := writeVersion(ctx, pool.DB, prev, false); err != nil {
			return err
		}
	}
	return nil
}

// MigrateVersion returns the current version + dirty flag.
func MigrateVersion(ctx context.Context, cfg config.DBConfig) (uint, bool, error) {
	pool, err := Open(cfg)
	if err != nil {
		return 0, false, err
	}
	defer pool.Close()
	if err := ensureMigrationsTable(ctx, pool.DB); err != nil {
		return 0, false, err
	}
	return readVersion(ctx, pool.DB)
}
