package nodes

import (
	"context"
	"crypto/rand"
	"database/sql"
	"net/netip"
	"os"
	"testing"
	"time"

	_ "github.com/go-sql-driver/mysql"

	"github.com/aidotvpn/server/internal/audit"
	"github.com/aidotvpn/server/internal/domain"
)

func defaultTenantID() domain.ID {
	id, _ := domain.ParseID("019650000000700080000000000000A1")
	return id
}

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

func resetDB(t *testing.T, db *sql.DB) {
	t.Helper()
	stmts := []string{
		"SET FOREIGN_KEY_CHECKS=0",
		"TRUNCATE TABLE audit_log",
		"TRUNCATE TABLE sessions",
		"TRUNCATE TABLE device_psks",
		"TRUNCATE TABLE device_keys",
		"TRUNCATE TABLE devices",
		"TRUNCATE TABLE node_endpoints",
		"TRUNCATE TABLE nodes",
		"TRUNCATE TABLE users",
		"SET FOREIGN_KEY_CHECKS=1",
	}
	for _, s := range stmts {
		if _, err := db.Exec(s); err != nil {
			t.Fatalf("reset (%s): %v", s, err)
		}
	}
}

// seedNodeFleet creates a node, a user, and N devices with active keys
// for use in Sync / ReportSessions tests. Returns the node ID and the
// list of device pubkeys.
func seedNodeFleet(t *testing.T, db *sql.DB, deviceCount int) (domain.ID, [][]byte) {
	t.Helper()

	tenantID := defaultTenantID()

	// Node
	nodeID := domain.NewID()
	nodePub := make([]byte, 32)
	_, _ = rand.Read(nodePub)
	_, err := db.Exec(`
		INSERT INTO nodes (id, tenant_id, hostname, region, public_key, status)
		VALUES (?, ?, ?, ?, ?, 'active')`,
		nodeID.Bytes(), tenantID.Bytes(),
		"test-node-"+nodeID.String(), "test-region", nodePub)
	if err != nil {
		t.Fatalf("seed node: %v", err)
	}

	// User
	userID := domain.NewID()
	_, err = db.Exec(`
		INSERT INTO users (id, tenant_id, kc_subject, email, display_name)
		VALUES (?, ?, ?, ?, ?)`,
		userID.Bytes(), tenantID.Bytes(),
		"kc-test-"+userID.String(),
		"node-test-"+userID.String()+"@example.com",
		"Node Test User")
	if err != nil {
		t.Fatalf("seed user: %v", err)
	}

	// Devices + keys + PSKs
	pubkeys := make([][]byte, 0, deviceCount)
	for i := 0; i < deviceCount; i++ {
		devID := domain.NewID()
		// install_id is CHAR(36) — must be a UUIDv4-shaped string, not a
		// prefix+id concatenation that overflows.
		installID := domain.NewID().String()
		_, err = db.Exec(`
			INSERT INTO devices (id, tenant_id, user_id, install_id,
			                    display_name, platform, status)
			VALUES (?, ?, ?, ?, ?, 'android', 'active')`,
			devID.Bytes(), tenantID.Bytes(), userID.Bytes(),
			installID, "test-device-"+string(rune('A'+i)))
		if err != nil {
			t.Fatalf("seed device %d: %v", i, err)
		}

		pub := make([]byte, 32)
		_, _ = rand.Read(pub)
		v4 := []byte{10, 78, byte(i / 256), byte(i % 256)}
		dkID := domain.NewID()
		_, err = db.Exec(`
			INSERT INTO device_keys (id, device_id, public_key, ipv4_addr, activated_at)
			VALUES (?, ?, ?, ?, NOW(6))`,
			dkID.Bytes(), devID.Bytes(), pub, v4)
		if err != nil {
			t.Fatalf("seed key %d: %v", i, err)
		}

		psk := make([]byte, 32)
		_, _ = rand.Read(psk)
		_, err = db.Exec(`
			INSERT INTO device_psks (id, device_key_id, psk, source)
			VALUES (?, ?, ?, 'classical')`,
			domain.NewID().Bytes(), dkID.Bytes(), psk)
		if err != nil {
			t.Fatalf("seed psk %d: %v", i, err)
		}

		pubkeys = append(pubkeys, pub)
	}

	return nodeID, pubkeys
}

func TestSync_ReturnsActivePeers_Integration(t *testing.T) {
	db := requireTestDB(t)
	resetDB(t, db)
	nodeID, _ := seedNodeFleet(t, db, 3)

	svc, err := New(Config{DB: db, Audit: audit.New(db)})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	res, err := svc.Sync(context.Background(), nodeID, "")
	if err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if res.NotModified {
		t.Error("first call should not be NotModified")
	}
	if len(res.Peers) != 3 {
		t.Errorf("got %d peers, want 3", len(res.Peers))
	}
	for _, p := range res.Peers {
		if len(p.PublicKey) != 32 {
			t.Errorf("public key length: %d", len(p.PublicKey))
		}
		if len(p.PSK) != 32 {
			t.Errorf("PSK length: %d", len(p.PSK))
		}
		if len(p.AllowedIPs) == 0 {
			t.Error("expected at least one AllowedIP")
		}
		if p.PersistentKeepaliveSeconds != 25 {
			t.Errorf("keepalive: %d", p.PersistentKeepaliveSeconds)
		}
	}
	if res.Version == "" {
		t.Error("expected non-empty version")
	}
}

func TestSync_NotModified_OnSameVersion_Integration(t *testing.T) {
	db := requireTestDB(t)
	resetDB(t, db)
	nodeID, _ := seedNodeFleet(t, db, 2)

	svc, _ := New(Config{DB: db, Audit: audit.New(db)})

	first, err := svc.Sync(context.Background(), nodeID, "")
	if err != nil {
		t.Fatalf("first Sync: %v", err)
	}
	second, err := svc.Sync(context.Background(), nodeID, first.Version)
	if err != nil {
		t.Fatalf("second Sync: %v", err)
	}
	if !second.NotModified {
		t.Error("expected NotModified on second call with same version")
	}
	if len(second.Peers) != 0 {
		t.Errorf("NotModified response should have empty peers, got %d", len(second.Peers))
	}
	if second.Version != first.Version {
		t.Errorf("version drift: %q vs %q", second.Version, first.Version)
	}
}

func TestSync_VersionChanges_AfterRevoke_Integration(t *testing.T) {
	db := requireTestDB(t)
	resetDB(t, db)
	nodeID, _ := seedNodeFleet(t, db, 3)

	svc, _ := New(Config{DB: db, Audit: audit.New(db)})

	first, err := svc.Sync(context.Background(), nodeID, "")
	if err != nil {
		t.Fatalf("first Sync: %v", err)
	}
	if len(first.Peers) != 3 {
		t.Fatalf("first Sync returned %d peers, want 3", len(first.Peers))
	}

	// Revoke one key. We use a CTE-style SELECT first to avoid MariaDB's
	// "can't reopen table being updated in subquery" rule on some versions.
	var devIDToRevoke []byte
	if err := db.QueryRow(`SELECT id FROM devices LIMIT 1`).Scan(&devIDToRevoke); err != nil {
		t.Fatalf("pick device: %v", err)
	}
	_, err = db.Exec(`UPDATE device_keys SET revoked_at = NOW(6) WHERE device_id = ?`,
		devIDToRevoke)
	if err != nil {
		t.Fatalf("revoke: %v", err)
	}

	second, err := svc.Sync(context.Background(), nodeID, first.Version)
	if err != nil {
		t.Fatalf("Sync after revoke: %v", err)
	}
	if second.NotModified {
		t.Error("revocation should change version, but NotModified=true")
	}
	if len(second.Peers) != 2 {
		t.Errorf("got %d peers after revoke, want 2", len(second.Peers))
	}
	if second.Version == first.Version {
		t.Error("version should differ after peer set change")
	}
}

func TestSync_MarksNodeSeen_Integration(t *testing.T) {
	db := requireTestDB(t)
	resetDB(t, db)
	nodeID, _ := seedNodeFleet(t, db, 1)

	svc, _ := New(Config{DB: db, Audit: audit.New(db)})

	// Wait a moment so last_seen_at change is observable.
	time.Sleep(50 * time.Millisecond)
	_, err := svc.Sync(context.Background(), nodeID, "")
	if err != nil {
		t.Fatalf("Sync: %v", err)
	}

	var seenAt sql.NullTime
	err = db.QueryRow(`SELECT last_seen_at FROM nodes WHERE id = ?`, nodeID.Bytes()).Scan(&seenAt)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if !seenAt.Valid {
		t.Fatal("last_seen_at not updated by Sync")
	}
}

func TestReportSessions_NewAndUpdate_Integration(t *testing.T) {
	db := requireTestDB(t)
	resetDB(t, db)
	nodeID, pubkeys := seedNodeFleet(t, db, 2)

	svc, _ := New(Config{DB: db, Audit: audit.New(db)})

	// First report — both should INSERT.
	t1 := time.Now().UTC().Truncate(time.Microsecond)
	stats := []SessionStat{
		{PeerPublicKey: pubkeys[0], LastHandshake: t1, RxBytes: 100, TxBytes: 200},
		{PeerPublicKey: pubkeys[1], LastHandshake: t1, RxBytes: 50, TxBytes: 75},
	}
	acc, rej, err := svc.ReportSessions(context.Background(), nodeID, stats)
	if err != nil {
		t.Fatalf("ReportSessions: %v", err)
	}
	if acc != 2 || rej != 0 {
		t.Errorf("first report: accepted=%d rejected=%d, want (2,0)", acc, rej)
	}
	var count int
	_ = db.QueryRow(`SELECT COUNT(*) FROM sessions WHERE ended_at IS NULL`).Scan(&count)
	if count != 2 {
		t.Errorf("after first report, open sessions = %d, want 2", count)
	}

	// Second report — should UPDATE the same rows, not insert new ones.
	t2 := t1.Add(30 * time.Second)
	stats[0].RxBytes = 5000
	stats[0].TxBytes = 6000
	stats[0].LastHandshake = t2
	stats[1].RxBytes = 100
	stats[1].TxBytes = 200
	stats[1].LastHandshake = t2
	acc, rej, err = svc.ReportSessions(context.Background(), nodeID, stats)
	if err != nil {
		t.Fatalf("second ReportSessions: %v", err)
	}
	if acc != 2 || rej != 0 {
		t.Errorf("second report: accepted=%d rejected=%d, want (2,0)", acc, rej)
	}
	_ = db.QueryRow(`SELECT COUNT(*) FROM sessions WHERE ended_at IS NULL`).Scan(&count)
	if count != 2 {
		t.Errorf("after second report, open sessions = %d, want 2 (UPDATE not INSERT)", count)
	}
	// Verify the bytes were actually updated.
	var rx, tx int64
	_ = db.QueryRow(`SELECT rx_bytes, tx_bytes FROM sessions WHERE device_key_id =
		(SELECT id FROM device_keys WHERE public_key = ?) AND ended_at IS NULL`,
		pubkeys[0]).Scan(&rx, &tx)
	if rx != 5000 || tx != 6000 {
		t.Errorf("bytes not updated: rx=%d tx=%d", rx, tx)
	}
}

func TestReportSessions_RejectsUnknownPubkey_Integration(t *testing.T) {
	db := requireTestDB(t)
	resetDB(t, db)
	nodeID, pubkeys := seedNodeFleet(t, db, 1)

	svc, _ := New(Config{DB: db, Audit: audit.New(db)})

	bogus := make([]byte, 32)
	_, _ = rand.Read(bogus)

	stats := []SessionStat{
		{PeerPublicKey: pubkeys[0], LastHandshake: time.Now().UTC()},
		{PeerPublicKey: bogus, LastHandshake: time.Now().UTC()},
	}
	acc, rej, err := svc.ReportSessions(context.Background(), nodeID, stats)
	if err != nil {
		t.Fatalf("ReportSessions: %v", err)
	}
	if acc != 1 {
		t.Errorf("accepted: %d, want 1", acc)
	}
	if rej != 1 {
		t.Errorf("rejected: %d, want 1", rej)
	}
}

func TestReportSessions_PreservesClientIP_Integration(t *testing.T) {
	db := requireTestDB(t)
	resetDB(t, db)
	nodeID, pubkeys := seedNodeFleet(t, db, 1)

	svc, _ := New(Config{DB: db, Audit: audit.New(db)})

	addr, _ := netip.ParseAddr("203.0.113.42")
	stats := []SessionStat{
		{
			PeerPublicKey: pubkeys[0],
			LastHandshake: time.Now().UTC(),
			RxBytes:       1, TxBytes: 1,
			ClientIP: addr,
		},
	}
	if _, _, err := svc.ReportSessions(context.Background(), nodeID, stats); err != nil {
		t.Fatalf("ReportSessions: %v", err)
	}
	var ipBytes []byte
	err := db.QueryRow(`SELECT client_ip FROM sessions WHERE ended_at IS NULL LIMIT 1`).Scan(&ipBytes)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	got, err := domain.IPFromBytes(ipBytes)
	if err != nil {
		t.Fatalf("ip parse: %v", err)
	}
	if got != addr {
		t.Errorf("client IP: %v, want %v", got, addr)
	}
}
