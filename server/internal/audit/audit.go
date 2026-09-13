// Package audit writes hash-chained audit log entries to MariaDB.
//
// Why a hash chain:
//
//	Each row stores `prev_hash` and `hash`. The hash is computed as
//	SHA-256(prev_hash || canonicalJSON(entry)). If any historical row is
//	mutated or removed, the next row's prev_hash no longer matches the
//	recomputed value of the predecessor's hash, so tampering becomes
//	detectable on a Verify() walk.
//
// Why canonical JSON:
//
//	Plain encoding/json does not give us reproducible byte output (map
//	ordering is randomized). We use a small canonical-JSON encoder that
//	sorts map keys lexicographically and elides whitespace.
//
// Concurrency:
//
//	The append path serializes around a SELECT ... FOR UPDATE on the most
//	recent row to prevent two appenders from chaining off the same predecessor.
//	Throughput is therefore bounded by single-row contention; for the AidotVpn
//	workload (administrative actions, device events) this is more than enough.
package audit

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"time"

	"github.com/aidotvpn/server/internal/domain"
)

// ActorKind enumerates the kind of subject that produced an event.
// Matches the ENUM in the audit_log table.
type ActorKind string

const (
	ActorUser   ActorKind = "user"
	ActorDevice ActorKind = "device"
	ActorNode   ActorKind = "node"
	ActorSystem ActorKind = "system"
)

// Entry is one audit row, as it appears in code.
//
// We deliberately omit Seq, PrevHash, and Hash from the input shape: those
// are computed by Append. Callers don't get to set them.
type Entry struct {
	ID         domain.ID      `json:"id"`
	TenantID   domain.ID      `json:"tenant_id"`
	ActorKind  ActorKind      `json:"actor_kind"`
	ActorID    *domain.ID     `json:"actor_id,omitempty"` // nil for system actors
	Action     string         `json:"action"`
	TargetKind string         `json:"target_kind,omitempty"`
	TargetID   *domain.ID     `json:"target_id,omitempty"`
	Details    map[string]any `json:"details,omitempty"`
	OccurredAt time.Time      `json:"occurred_at"` // UTC
}

// Writer appends entries to the audit_log table.
type Writer struct {
	db *sql.DB
}

// New returns a Writer bound to the given database.
func New(db *sql.DB) *Writer {
	return &Writer{db: db}
}

// Append writes one entry, computing the hash chain. The Entry is filled in
// as needed (ID, OccurredAt) before being written.
//
// The function is goroutine-safe; concurrent callers will serialize through
// the database lock.
func (w *Writer) Append(ctx context.Context, e Entry) error {
	if e.ID.IsZero() {
		e.ID = domain.NewID()
	}
	if e.OccurredAt.IsZero() {
		e.OccurredAt = time.Now().UTC()
	} else {
		e.OccurredAt = e.OccurredAt.UTC()
	}
	// MariaDB TIMESTAMP(6) only stores microseconds; truncating here
	// guarantees that the hash we compute matches what Verify will compute
	// after reading the row back.
	e.OccurredAt = e.OccurredAt.Truncate(time.Microsecond)
	if e.Action == "" {
		return fmt.Errorf("audit: action is required")
	}
	if e.TenantID.IsZero() {
		return fmt.Errorf("audit: tenant_id is required")
	}
	if e.ActorKind == "" {
		return fmt.Errorf("audit: actor_kind is required")
	}

	tx, err := w.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return fmt.Errorf("audit: begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }() // safe to call after Commit

	// Lock the chain tail. SELECT ... FOR UPDATE returns the latest hash, or
	// no rows if this is the very first audit entry.
	var prevHash []byte
	row := tx.QueryRowContext(ctx,
		`SELECT hash FROM audit_log ORDER BY seq DESC LIMIT 1 FOR UPDATE`)
	switch err := row.Scan(&prevHash); err {
	case nil:
		// have a predecessor
	case sql.ErrNoRows:
		prevHash = nil
	default:
		return fmt.Errorf("audit: read prev hash: %w", err)
	}

	// Build the canonical bytes: prev_hash || canonical_json(entry).
	canon, err := canonicalJSON(e)
	if err != nil {
		return fmt.Errorf("audit: canonical JSON: %w", err)
	}
	h := sha256.New()
	h.Write(prevHash) // safe even when nil (writes 0 bytes)
	h.Write(canon)
	hash := h.Sum(nil)

	// Marshal details for the JSON column.
	var detailsJSON []byte
	if e.Details != nil {
		detailsJSON, err = json.Marshal(e.Details)
		if err != nil {
			return fmt.Errorf("audit: marshal details: %w", err)
		}
	}

	// Resolve nullable actor_id / target_id.
	var actorIDArg, targetIDArg any
	if e.ActorID != nil {
		actorIDArg = e.ActorID.Bytes()
	}
	if e.TargetID != nil {
		targetIDArg = e.TargetID.Bytes()
	}
	var prevHashArg any
	if prevHash != nil {
		prevHashArg = prevHash
	}
	var targetKindArg any
	if e.TargetKind != "" {
		targetKindArg = e.TargetKind
	}

	_, err = tx.ExecContext(ctx, `
		INSERT INTO audit_log
			(id, tenant_id, actor_kind, actor_id, action, target_kind, target_id,
			 details, prev_hash, hash, occurred_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		e.ID.Bytes(), e.TenantID.Bytes(), string(e.ActorKind), actorIDArg,
		e.Action, targetKindArg, targetIDArg,
		nullableJSON(detailsJSON), prevHashArg, hash, e.OccurredAt)
	if err != nil {
		return fmt.Errorf("audit: insert: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("audit: commit: %w", err)
	}
	return nil
}

// Verify walks the audit chain in [fromSeq, toSeq] (inclusive) and returns
// the first row whose hash does not match the recomputed value, or nil if
// the segment is intact. Pass toSeq=0 to walk to the end.
//
// Verify reads in batches of 1000 rows to bound memory. We don't take a
// lock; callers should expect false-positive failures if writes are
// happening concurrently with verification — run it during quiet windows.
func (w *Writer) Verify(ctx context.Context, fromSeq, toSeq uint64) (*Entry, error) {
	const batch = 1000
	cursor := fromSeq
	var prevHash []byte

	if cursor > 0 {
		// Need the predecessor's hash to validate the first row in the range.
		row := w.db.QueryRowContext(ctx,
			`SELECT hash FROM audit_log WHERE seq < ? ORDER BY seq DESC LIMIT 1`,
			cursor)
		switch err := row.Scan(&prevHash); err {
		case nil, sql.ErrNoRows:
		default:
			return nil, fmt.Errorf("audit verify: load anchor hash: %w", err)
		}
	}

	for {
		rows, err := w.db.QueryContext(ctx, `
			SELECT seq, id, tenant_id, actor_kind, actor_id, action,
			       target_kind, target_id, details, prev_hash, hash, occurred_at
			FROM audit_log
			WHERE seq >= ? AND (? = 0 OR seq <= ?)
			ORDER BY seq ASC LIMIT ?`,
			cursor, toSeq, toSeq, batch)
		if err != nil {
			return nil, fmt.Errorf("audit verify: query: %w", err)
		}

		count := 0
		var nextCursor uint64
		for rows.Next() {
			var (
				seq        uint64
				id, tenant []byte
				actorKind  string
				actorID    []byte // nullable
				action     string
				targetKind sql.NullString
				targetID   []byte // nullable
				details    sql.NullString
				prev, hash []byte
				occurredAt time.Time
			)
			if err := rows.Scan(&seq, &id, &tenant, &actorKind, &actorID,
				&action, &targetKind, &targetID, &details, &prev, &hash,
				&occurredAt); err != nil {
				_ = rows.Close()
				return nil, fmt.Errorf("audit verify: scan: %w", err)
			}

			// Recompute.
			e := Entry{
				ActorKind:  ActorKind(actorKind),
				Action:     action,
				OccurredAt: occurredAt.UTC(),
			}
			_ = e.ID.Scan(id)
			_ = e.TenantID.Scan(tenant)
			if actorID != nil {
				var aid domain.ID
				_ = aid.Scan(actorID)
				e.ActorID = &aid
			}
			if targetKind.Valid {
				e.TargetKind = targetKind.String
			}
			if targetID != nil {
				var tid domain.ID
				_ = tid.Scan(targetID)
				e.TargetID = &tid
			}
			if details.Valid {
				m := map[string]any{}
				if err := json.Unmarshal([]byte(details.String), &m); err != nil {
					_ = rows.Close()
					return nil, fmt.Errorf("audit verify: details unmarshal seq=%d: %w", seq, err)
				}
				e.Details = m
			}

			canon, err := canonicalJSON(e)
			if err != nil {
				_ = rows.Close()
				return nil, fmt.Errorf("audit verify: canonical seq=%d: %w", seq, err)
			}
			h := sha256.New()
			h.Write(prevHash)
			h.Write(canon)
			expect := h.Sum(nil)

			if !bytesEqual(hash, expect) {
				_ = rows.Close()
				return &e, nil
			}
			prevHash = hash
			nextCursor = seq + 1
			count++
		}
		if err := rows.Close(); err != nil {
			return nil, fmt.Errorf("audit verify: close: %w", err)
		}
		if count == 0 {
			return nil, nil
		}
		cursor = nextCursor
		if toSeq != 0 && cursor > toSeq {
			return nil, nil
		}
	}
}

// --- helpers -----------------------------------------------------------

// nullableJSON returns nil when b is empty so MariaDB stores NULL.
func nullableJSON(b []byte) any {
	if len(b) == 0 {
		return nil
	}
	return string(b)
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// canonicalJSON encodes v with sorted map keys, no extra whitespace, and
// stable representations for time.Time (RFC 3339 nanosecond UTC) and
// domain.ID (lowercase hyphenated UUID).
//
// We accept the small overhead of two encode passes (once via reflection
// for the canonical form) in exchange for not pulling in a third-party
// library. This stays cleanly stdlib + our own types.
func canonicalJSON(v any) ([]byte, error) {
	// Two-stage strategy:
	//  1. Marshal with encoding/json so all our type Marshalers run.
	//  2. Decode into an interface{} and re-encode in canonical form.
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var generic any
	if err := json.Unmarshal(raw, &generic); err != nil {
		return nil, err
	}
	return canonicalEncode(generic), nil
}

func canonicalEncode(v any) []byte {
	switch x := v.(type) {
	case nil:
		return []byte("null")
	case bool:
		if x {
			return []byte("true")
		}
		return []byte("false")
	case float64:
		// JSON numbers come back as float64. We render integers without a
		// decimal so {"n": 1} canonicalises to {"n":1} not {"n":1.0}.
		if x == float64(int64(x)) {
			return []byte(strconv.FormatInt(int64(x), 10))
		}
		return []byte(strconv.FormatFloat(x, 'g', -1, 64))
	case string:
		// Use encoding/json to escape correctly.
		out, _ := json.Marshal(x)
		return out
	case []any:
		var buf []byte
		buf = append(buf, '[')
		for i, item := range x {
			if i > 0 {
				buf = append(buf, ',')
			}
			buf = append(buf, canonicalEncode(item)...)
		}
		buf = append(buf, ']')
		return buf
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		var buf []byte
		buf = append(buf, '{')
		for i, k := range keys {
			if i > 0 {
				buf = append(buf, ',')
			}
			kv, _ := json.Marshal(k)
			buf = append(buf, kv...)
			buf = append(buf, ':')
			buf = append(buf, canonicalEncode(x[k])...)
		}
		buf = append(buf, '}')
		return buf
	default:
		// Fall back to plain JSON for anything we didn't anticipate.
		out, _ := json.Marshal(v)
		return out
	}
}

// ListByTenant returns the most recent audit entries for a tenant, newest
// first. Use cursor=last entry's seq from the previous page to paginate.
//
// We deliberately do NOT verify the hash chain on this read path; that's
// what Verify() is for. Verifying every read would be expensive for a
// timeline screen that polls regularly. Mutation detection happens out of
// band via Verify() either on demand from the admin console or on a
// periodic schedule.
// ListByTenant returns a page of entries, newest first.
//
// from/to bound the period; zero values mean unbounded. An audit log
// without a date range is only usable for "what happened just now" —
// the question it is actually kept for is "what happened on the day of
// the incident", and that needs a period.
func (w *Writer) ListByTenant(ctx context.Context, tenantID domain.ID, limit int, cursor uint64, from, to time.Time) ([]ListedEntry, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	// cursor=0 means "from the latest"; otherwise we want entries with
	// seq < cursor (older than the last item from the previous page).
	q := `
		SELECT seq, id, actor_kind, actor_id, action, target_kind, target_id, details, occurred_at
		FROM audit_log
		WHERE tenant_id = ?
	`
	args := []any{tenantID.Bytes()}
	if cursor > 0 {
		q += ` AND seq < ?`
		args = append(args, cursor)
	}
	if !from.IsZero() {
		q += ` AND occurred_at >= ?`
		args = append(args, from)
	}
	if !to.IsZero() {
		q += ` AND occurred_at < ?`
		args = append(args, to)
	}
	q += ` ORDER BY seq DESC LIMIT ?`
	args = append(args, limit)

	rows, err := w.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("audit.ListByTenant: %w", err)
	}
	defer rows.Close()

	var out []ListedEntry
	for rows.Next() {
		var (
			le            ListedEntry
			actorIDBytes  []byte
			targetIDBytes []byte
			targetKind    sql.NullString
			detailsRaw    []byte
			idBytes       []byte
		)
		if err := rows.Scan(&le.Seq, &idBytes, &le.ActorKind, &actorIDBytes,
			&le.Action, &targetKind, &targetIDBytes, &detailsRaw, &le.OccurredAt); err != nil {
			return nil, fmt.Errorf("audit.ListByTenant scan: %w", err)
		}
		if err := le.ID.Scan(idBytes); err != nil {
			return nil, err
		}
		if len(actorIDBytes) > 0 {
			var aid domain.ID
			if err := aid.Scan(actorIDBytes); err != nil {
				return nil, err
			}
			le.ActorID = aid.String()
		}
		if targetKind.Valid {
			le.TargetKind = targetKind.String
		}
		if len(targetIDBytes) > 0 {
			var tid domain.ID
			if err := tid.Scan(targetIDBytes); err != nil {
				return nil, err
			}
			le.TargetID = tid.String()
		}
		if len(detailsRaw) > 0 && string(detailsRaw) != "null" {
			le.Details = json.RawMessage(detailsRaw)
		}
		out = append(out, le)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("audit.ListByTenant rows: %w", err)
	}
	return out, nil
}

// ListedEntry is the projection used by ListByTenant. Hex-encoded IDs make
// the JSON response straightforward for the console to render without
// custom decoders.
type ListedEntry struct {
	Seq        uint64          `json:"seq"`
	ID         domain.ID       `json:"id"`
	ActorKind  ActorKind       `json:"actor_kind"`
	ActorID    string          `json:"actor_id,omitempty"`
	Action     string          `json:"action"`
	TargetKind string          `json:"target_kind,omitempty"`
	TargetID   string          `json:"target_id,omitempty"`
	Details    json.RawMessage `json:"details,omitempty"`
	OccurredAt time.Time       `json:"occurred_at"`
}

// keep unused import warnings from biting us if we trim helpers later.
var _ = binary.BigEndian
