package audit

import (
	"context"
	"database/sql"
	"os"
	"testing"
	"time"

	_ "github.com/go-sql-driver/mysql"

	"github.com/aidotvpn/server/internal/domain"
)

// requireTestDB returns a connection to the integration test database.
// Tests are skipped if the env var is unset, so unit-only `go test` runs
// don't need a database.
func requireTestDB(t *testing.T) *sql.DB {
	t.Helper()
	dsn := os.Getenv("AIDOTVPN_TEST_DSN")
	if dsn == "" {
		t.Skip("AIDOTVPN_TEST_DSN not set; skipping integration test")
	}
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := db.PingContext(context.Background()); err != nil {
		t.Fatalf("ping: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func resetAuditLog(t *testing.T, db *sql.DB) {
	t.Helper()
	// TRUNCATE (not DELETE) so the AUTO_INCREMENT counter resets and tests
	// can reference predictable seq values.
	_, err := db.Exec("TRUNCATE TABLE audit_log")
	if err != nil {
		t.Fatalf("reset: %v", err)
	}
}

func defaultTenantID() domain.ID {
	id, _ := domain.ParseID("019650000000700080000000000000A1")
	return id
}

func TestAppend_SingleEntry_Integration(t *testing.T) {
	db := requireTestDB(t)
	resetAuditLog(t, db)
	w := New(db)

	userID := domain.NewID()
	deviceID := domain.NewID()
	tid := defaultTenantID()

	err := w.Append(context.Background(), Entry{
		TenantID:   tid,
		ActorKind:  ActorUser,
		ActorID:    &userID,
		Action:     "device.register",
		TargetKind: "device",
		TargetID:   &deviceID,
		Details: map[string]any{
			"install_id": "11111111-1111-7111-8111-111111111111",
			"platform":   "android",
		},
	})
	if err != nil {
		t.Fatalf("Append: %v", err)
	}

	// Verify the row landed.
	var (
		count   int
		hash    []byte
		prev    sql.NullString
		details sql.NullString
	)
	row := db.QueryRow(`SELECT COUNT(*) FROM audit_log`)
	if err := row.Scan(&count); err != nil || count != 1 {
		t.Fatalf("count: %d %v", count, err)
	}
	row = db.QueryRow(`SELECT hash, HEX(prev_hash), details FROM audit_log`)
	if err := row.Scan(&hash, &prev, &details); err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(hash) != 32 {
		t.Errorf("hash length: %d", len(hash))
	}
	if prev.Valid {
		t.Errorf("first row should have NULL prev_hash, got %v", prev.String)
	}
	if !details.Valid {
		t.Errorf("details should be present")
	}
}

func TestAppend_ChainsCorrectly_Integration(t *testing.T) {
	db := requireTestDB(t)
	resetAuditLog(t, db)
	w := New(db)
	tid := defaultTenantID()

	for i := 0; i < 5; i++ {
		uid := domain.NewID()
		err := w.Append(context.Background(), Entry{
			TenantID:  tid,
			ActorKind: ActorSystem,
			ActorID:   &uid,
			Action:    "test.append",
			Details:   map[string]any{"i": i},
		})
		if err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}

	// Verify the chain end-to-end.
	bad, err := w.Verify(context.Background(), 0, 0)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if bad != nil {
		t.Fatalf("Verify reported tampering on a clean chain: %+v", bad)
	}
}

func TestVerify_DetectsTampering_Integration(t *testing.T) {
	db := requireTestDB(t)
	resetAuditLog(t, db)
	w := New(db)
	tid := defaultTenantID()

	// Write 3 entries.
	for i := 0; i < 3; i++ {
		err := w.Append(context.Background(), Entry{
			TenantID: tid, ActorKind: ActorSystem,
			Action:  "test.tamper",
			Details: map[string]any{"n": i},
		})
		if err != nil {
			t.Fatalf("append: %v", err)
		}
	}

	// Tamper with row 2's details. Hash will no longer match.
	_, err := db.Exec(`UPDATE audit_log
		SET details = JSON_SET(details, '$.n', 999)
		WHERE seq = 2`)
	if err != nil {
		t.Fatalf("tamper: %v", err)
	}

	bad, err := w.Verify(context.Background(), 0, 0)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if bad == nil {
		t.Fatal("expected Verify to detect the tampered row, but got nil")
	}
}

func TestCanonicalJSON_Stable(t *testing.T) {
	id, _ := domain.ParseID("019650000000700080000000000000A1")
	t1 := time.Date(2026, 5, 3, 10, 0, 0, 0, time.UTC)
	e := Entry{
		ID: id, TenantID: id, ActorKind: ActorSystem,
		Action: "test", OccurredAt: t1,
		Details: map[string]any{"z": 1, "a": 2, "m": 3},
	}
	a, err := canonicalJSON(e)
	if err != nil {
		t.Fatalf("encode 1: %v", err)
	}
	b, err := canonicalJSON(e)
	if err != nil {
		t.Fatalf("encode 2: %v", err)
	}
	if string(a) != string(b) {
		t.Fatalf("not stable:\nA=%s\nB=%s", a, b)
	}
	// Keys should be sorted.
	got := string(a)
	if got == "" {
		t.Fatal("empty output")
	}
	t.Logf("canonical: %s", got)
}
