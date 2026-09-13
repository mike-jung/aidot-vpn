package devices

import (
	"context"
	"crypto/rand"
	"database/sql"
	"net/netip"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	_ "github.com/go-sql-driver/mysql"

	"github.com/aidotvpn/server/internal/audit"
	"github.com/aidotvpn/server/internal/auth"
	"github.com/aidotvpn/server/internal/domain"
)

func defaultTenantID() domain.ID {
	id, _ := domain.ParseID("019650000000700080000000000000A1")
	return id
}

// requireTestDB returns a connection to the integration test DB.
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

// resetDB wipes the rows the device tests touch so each test starts clean.
// We TRUNCATE in dependency order so FK checks pass.
func resetDB(t *testing.T, db *sql.DB) {
	t.Helper()
	stmts := []string{
		"SET FOREIGN_KEY_CHECKS=0",
		"TRUNCATE TABLE audit_log",
		"TRUNCATE TABLE device_psks",
		"TRUNCATE TABLE device_state_tokens",
		"TRUNCATE TABLE device_keys",
		"TRUNCATE TABLE device_group_memberships",
		"TRUNCATE TABLE attestation_records",
		"TRUNCATE TABLE client_certs",
		"TRUNCATE TABLE sessions",
		"TRUNCATE TABLE devices",
		"TRUNCATE TABLE user_group_memberships",
		"TRUNCATE TABLE users",
		"SET FOREIGN_KEY_CHECKS=1",
	}
	for _, s := range stmts {
		if _, err := db.Exec(s); err != nil {
			t.Fatalf("reset (%s): %v", s, err)
		}
	}
}

// seedUser creates a user that owns devices we register in tests.
func seedUser(t *testing.T, db *sql.DB) domain.ID {
	t.Helper()
	uid := domain.NewID()
	_, err := db.Exec(`
		INSERT INTO users (id, tenant_id, kc_subject, email, display_name)
		VALUES (?, ?, ?, ?, ?)`,
		uid.Bytes(), defaultTenantID().Bytes(),
		"kc-test-"+uid.String(),
		"alice-"+uid.String()+"@example.com",
		"Alice")
	if err != nil {
		t.Fatalf("seedUser: %v", err)
	}
	return uid
}

// makeService spins up a Service with a fresh test CA and audit writer.
func makeService(t *testing.T, db *sql.DB) *Service {
	t.Helper()
	ca, err := auth.NewCA(auth.CAOptions{CommonName: "test-ca"})
	if err != nil {
		t.Fatalf("NewCA: %v", err)
	}
	svc, err := New(Config{
		DB:       db,
		CA:       ca,
		Audit:    audit.New(db),
		TenantID: defaultTenantID(),
	})
	if err != nil {
		t.Fatalf("New service: %v", err)
	}
	return svc
}

func randomKey(t *testing.T) []byte {
	t.Helper()
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return b
}

func TestRegister_NewDevice_Integration(t *testing.T) {
	db := requireTestDB(t)
	resetDB(t, db)
	uid := seedUser(t, db)
	svc := makeService(t, db)

	res, err := svc.Register(context.Background(), RegisterParams{
		UserID:           uid,
		InstallID:        "11111111-1111-7111-8111-111111111111",
		DisplayName:      "Pixel 9 Pro",
		Platform:         PlatformAndroid,
		AppVersion:       "0.1.0",
		DevicePublicKey:  randomKey(t),
		AttestationToken: "stub-token", // moves to active
	})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if res.Device.Status != StatusActive {
		t.Errorf("status: got %q, want %q", res.Device.Status, StatusActive)
	}
	if !res.Allocation.DeviceKey.IPv4.IsValid() {
		t.Error("expected IPv4 allocation")
	}
	if !res.Allocation.DeviceKey.IPv6.IsValid() {
		t.Error("expected IPv6 allocation")
	}
	if len(res.Allocation.PSK.PSK) != 32 {
		t.Errorf("PSK length: %d", len(res.Allocation.PSK.PSK))
	}
	if len(res.Allocation.ClientCertPEM) == 0 {
		t.Error("missing client cert PEM")
	}
	if len(res.Allocation.CACertPEM) == 0 {
		t.Error("missing CA cert PEM")
	}

	// IP should be in the tenant's pool (10.78.0.0/16).
	pool, _ := netip.ParsePrefix("10.78.0.0/16")
	if !pool.Contains(res.Allocation.DeviceKey.IPv4) {
		t.Errorf("v4 %s not in pool %s", res.Allocation.DeviceKey.IPv4, pool)
	}
	// Allocator skips .0 and .1.
	addr := res.Allocation.DeviceKey.IPv4
	if addr.As4()[3] < 2 {
		t.Errorf("v4 %s should not be .0 or .1", addr)
	}
}

func TestRegister_ActiveWhenAttestationGateDisabled_Integration(t *testing.T) {
	db := requireTestDB(t)
	resetDB(t, db)
	uid := seedUser(t, db)
	svc := makeService(t, db)

	res, err := svc.Register(context.Background(), RegisterParams{
		UserID:          uid,
		InstallID:       "22222222-2222-7222-8222-222222222222",
		DisplayName:     "iPhone 17",
		Platform:        PlatformIOS,
		DevicePublicKey: randomKey(t),
		// No AttestationToken
	})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if res.Device.Status != StatusActive {
		t.Errorf("status: got %q, want %q (attestation gate disabled)", res.Device.Status, StatusActive)
	}
}

func TestRegister_Idempotent_SameInstallID_Integration(t *testing.T) {
	db := requireTestDB(t)
	resetDB(t, db)
	uid := seedUser(t, db)
	svc := makeService(t, db)

	install := "33333333-3333-7333-8333-333333333333"

	first, err := svc.Register(context.Background(), RegisterParams{
		UserID: uid, InstallID: install, DisplayName: "First name",
		Platform: PlatformAndroid, DevicePublicKey: randomKey(t),
		AttestationToken: "ok",
	})
	if err != nil {
		t.Fatalf("first Register: %v", err)
	}

	// Re-register with same install_id but different display name.
	second, err := svc.Register(context.Background(), RegisterParams{
		UserID: uid, InstallID: install, DisplayName: "Renamed device",
		Platform: PlatformAndroid, DevicePublicKey: randomKey(t),
		AttestationToken: "ok",
	})
	if err != nil {
		t.Fatalf("second Register: %v", err)
	}

	if first.Device.ID != second.Device.ID {
		t.Errorf("device id changed: %s vs %s", first.Device.ID, second.Device.ID)
	}
	if second.Device.DisplayName != "Renamed device" {
		t.Errorf("display name not updated: %q", second.Device.DisplayName)
	}

	// Old key should be revoked.
	var revoked int
	err = db.QueryRow(`SELECT COUNT(*) FROM device_keys WHERE device_id=? AND revoked_at IS NOT NULL`,
		first.Device.ID.Bytes()).Scan(&revoked)
	if err != nil || revoked < 1 {
		t.Errorf("expected at least 1 revoked old key, got %d (err=%v)", revoked, err)
	}
}

func TestRegister_DifferentInstallID_AllocatesDifferentIPs_Integration(t *testing.T) {
	db := requireTestDB(t)
	resetDB(t, db)
	uid := seedUser(t, db)
	svc := makeService(t, db)

	a, err := svc.Register(context.Background(), RegisterParams{
		UserID: uid, InstallID: "44444444-4444-7444-8444-444444444444",
		DisplayName: "device A", Platform: PlatformAndroid,
		DevicePublicKey: randomKey(t), AttestationToken: "ok",
	})
	if err != nil {
		t.Fatalf("Register A: %v", err)
	}
	b, err := svc.Register(context.Background(), RegisterParams{
		UserID: uid, InstallID: "55555555-5555-7555-8555-555555555555",
		DisplayName: "device B", Platform: PlatformAndroid,
		DevicePublicKey: randomKey(t), AttestationToken: "ok",
	})
	if err != nil {
		t.Fatalf("Register B: %v", err)
	}
	if a.Allocation.DeviceKey.IPv4 == b.Allocation.DeviceKey.IPv4 {
		t.Errorf("two devices got same v4: %s", a.Allocation.DeviceKey.IPv4)
	}
	if a.Allocation.DeviceKey.IPv6 == b.Allocation.DeviceKey.IPv6 {
		t.Errorf("two devices got same v6: %s", a.Allocation.DeviceKey.IPv6)
	}
}

func TestRegister_RejectsInvalidParams(t *testing.T) {
	db := requireTestDB(t)
	resetDB(t, db)
	uid := seedUser(t, db)
	svc := makeService(t, db)

	cases := []struct {
		name string
		p    RegisterParams
	}{
		{"zero user", RegisterParams{
			InstallID: "x", DisplayName: "n", Platform: PlatformAndroid,
			DevicePublicKey: make([]byte, 32),
		}},
		{"empty install", RegisterParams{
			UserID: uid, DisplayName: "n", Platform: PlatformAndroid,
			DevicePublicKey: make([]byte, 32),
		}},
		{"empty display", RegisterParams{
			UserID: uid, InstallID: "x", Platform: PlatformAndroid,
			DevicePublicKey: make([]byte, 32),
		}},
		{"bad pubkey length", RegisterParams{
			UserID: uid, InstallID: "x", DisplayName: "n", Platform: PlatformAndroid,
			DevicePublicKey: []byte{1, 2, 3},
		}},
		{"unknown platform", RegisterParams{
			UserID: uid, InstallID: "x", DisplayName: "n", Platform: "klingon",
			DevicePublicKey: make([]byte, 32),
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := svc.Register(context.Background(), c.p); err == nil {
				t.Error("expected error")
			}
		})
	}
}

func TestRotateKey_PreservesIPs_Integration(t *testing.T) {
	db := requireTestDB(t)
	resetDB(t, db)
	uid := seedUser(t, db)
	svc := makeService(t, db)

	first, err := svc.Register(context.Background(), RegisterParams{
		UserID: uid, InstallID: "66666666-6666-7666-8666-666666666666",
		DisplayName: "rotate-me", Platform: PlatformAndroid,
		DevicePublicKey: randomKey(t), AttestationToken: "ok",
	})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	originalV4 := first.Allocation.DeviceKey.IPv4
	originalV6 := first.Allocation.DeviceKey.IPv6
	originalPSK := first.Allocation.PSK.PSK

	newPubKey := randomKey(t)
	rot, err := svc.RotateKey(context.Background(), RotateKeyParams{
		DeviceID:           first.Device.ID,
		NewDevicePublicKey: newPubKey,
	})
	if err != nil {
		t.Fatalf("RotateKey: %v", err)
	}

	if rot.Allocation.DeviceKey.IPv4 != originalV4 {
		t.Errorf("v4 changed across rotation: %s -> %s", originalV4, rot.Allocation.DeviceKey.IPv4)
	}
	if rot.Allocation.DeviceKey.IPv6 != originalV6 {
		t.Errorf("v6 changed across rotation: %s -> %s", originalV6, rot.Allocation.DeviceKey.IPv6)
	}
	if string(rot.Allocation.PSK.PSK) == string(originalPSK) {
		t.Error("PSK should rotate alongside key (entropy concern)")
	}
	if string(rot.Allocation.DeviceKey.PublicKey) != string(newPubKey) {
		t.Error("new public key not stored")
	}
}

func TestRotateKey_RejectsRevokedDevice_Integration(t *testing.T) {
	db := requireTestDB(t)
	resetDB(t, db)
	uid := seedUser(t, db)
	svc := makeService(t, db)

	reg, err := svc.Register(context.Background(), RegisterParams{
		UserID: uid, InstallID: "77777777-7777-7777-8777-777777777777",
		DisplayName: "to-revoke", Platform: PlatformAndroid,
		DevicePublicKey: randomKey(t), AttestationToken: "ok",
	})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if err := svc.Revoke(context.Background(), reg.Device.ID, uid, "user request"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	_, err = svc.RotateKey(context.Background(), RotateKeyParams{
		DeviceID:           reg.Device.ID,
		NewDevicePublicKey: randomKey(t),
	})
	if err == nil {
		t.Error("RotateKey on revoked device should fail")
	}
}

func TestListMyDevices_Integration(t *testing.T) {
	db := requireTestDB(t)
	resetDB(t, db)
	uid := seedUser(t, db)
	svc := makeService(t, db)

	for i := 0; i < 3; i++ {
		_, err := svc.Register(context.Background(), RegisterParams{
			UserID: uid,
			InstallID: "8888" + string(rune('a'+i)) + string(rune('a'+i)) +
				string(rune('a'+i)) + string(rune('a'+i)) + "-7888-8888-888888888888",
			DisplayName:      "device " + string(rune('A'+i)),
			Platform:         PlatformAndroid,
			DevicePublicKey:  randomKey(t),
			AttestationToken: "ok",
		})
		if err != nil {
			t.Fatalf("Register %d: %v", i, err)
		}
	}

	devs, err := svc.ListMyDevices(context.Background(), uid)
	if err != nil {
		t.Fatalf("ListMyDevices: %v", err)
	}
	if len(devs) != 3 {
		t.Errorf("got %d devices, want 3", len(devs))
	}
	// Newest-first ordering.
	for i := 1; i < len(devs); i++ {
		if devs[i-1].CreatedAt.Before(devs[i].CreatedAt) {
			t.Errorf("ordering: [%d]=%v before [%d]=%v",
				i-1, devs[i-1].CreatedAt, i, devs[i].CreatedAt)
		}
	}
}

func TestRevoke_AuditTrailRecords_Integration(t *testing.T) {
	db := requireTestDB(t)
	resetDB(t, db)
	uid := seedUser(t, db)
	svc := makeService(t, db)

	reg, err := svc.Register(context.Background(), RegisterParams{
		UserID: uid, InstallID: "99999999-9999-7999-8999-999999999999",
		DisplayName: "audit-me", Platform: PlatformAndroid,
		DevicePublicKey: randomKey(t), AttestationToken: "ok",
	})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	if err := svc.Revoke(context.Background(), reg.Device.ID, uid, "compromise suspected"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	var actions []string
	rows, err := db.Query(`SELECT action FROM audit_log ORDER BY seq ASC`)
	if err != nil {
		t.Fatalf("audit query: %v", err)
	}
	defer rows.Close()
	for rows.Next() {
		var a string
		if err := rows.Scan(&a); err != nil {
			t.Fatalf("scan: %v", err)
		}
		actions = append(actions, a)
	}
	want := []string{"device.register", "device.revoke"}
	if len(actions) != len(want) {
		t.Fatalf("audit actions: got %v, want %v", actions, want)
	}
	for i := range want {
		if actions[i] != want[i] {
			t.Errorf("audit[%d]: got %q, want %q", i, actions[i], want[i])
		}
	}

	// And device should be soft-deleted.
	var deletedAt sql.NullTime
	err = db.QueryRow(`SELECT deleted_at FROM devices WHERE id=?`, reg.Device.ID.Bytes()).Scan(&deletedAt)
	if err != nil {
		t.Fatalf("deleted_at query: %v", err)
	}
	if !deletedAt.Valid {
		t.Error("deleted_at not set after Revoke")
	}
}

// Suppress potential unused-import warning if helper trimmed.
var _ = time.Second

// ============================================================
// Phase 8: per-app split tunnel — UpdateAppFilter unit tests
// ============================================================

func TestUpdateAppFilter_RejectsBadMode(t *testing.T) {
	svc := &Service{} // no DB needed for argument validation
	err := svc.UpdateAppFilter(context.Background(),
		domain.NewID(), domain.NewID(), AppFilterMode("garbage"), nil)
	if err == nil {
		t.Fatal("expected error for invalid mode")
	}
}

func TestUpdateAppFilter_RejectsZeroDeviceID(t *testing.T) {
	svc := &Service{}
	err := svc.UpdateAppFilter(context.Background(),
		domain.ID{}, domain.NewID(), AppFilterInclude, nil)
	if err == nil {
		t.Fatal("expected error for zero deviceID")
	}
}

func TestValidatePackageName(t *testing.T) {
	tests := []struct {
		name    string
		pkg     string
		wantErr bool
	}{
		{"valid simple", "com.example.app", false},
		{"valid with underscore", "com.example_corp.app1", false},
		{"valid mixed case", "com.Example.App", false},
		{"empty", "", true},
		{"no dot", "noseparator", true},
		{"shell metachar", "com.example;rm -rf", true},
		{"path traversal", "../etc/passwd", true},
		{"unicode", "com.example.앱", true},
		{"too long", strings.Repeat("a", 256) + ".app", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validatePackageName(tc.pkg)
			if tc.wantErr && err == nil {
				t.Errorf("validatePackageName(%q): want error, got nil", tc.pkg)
			}
			if !tc.wantErr && err != nil {
				t.Errorf("validatePackageName(%q): want no error, got %v", tc.pkg, err)
			}
		})
	}
}

func TestUpdateAppFilter_PersistsAndRoundTrips_Integration(t *testing.T) {
	db := requireTestDB(t)
	resetDB(t, db)
	uid := seedUser(t, db)
	svc := makeService(t, db)

	reg, err := svc.Register(context.Background(), RegisterParams{
		UserID:          uid,
		InstallID:       "33333333-3333-7333-8333-333333333333",
		DisplayName:     "Test Phone",
		Platform:        PlatformAndroid,
		DevicePublicKey: randomKey(t),
	})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	// New device defaults to off + empty.
	if got := reg.Allocation.AppFilter.Mode; got != AppFilterOff {
		t.Errorf("default mode: got %q, want %q", got, AppFilterOff)
	}

	// Apply include rule with two packages, one duplicate, one with whitespace.
	err = svc.UpdateAppFilter(context.Background(), reg.Device.ID, uid,
		AppFilterInclude,
		[]string{"com.acme.app1", "com.acme.app1", "  com.acme.app2  "},
	)
	if err != nil {
		t.Fatalf("UpdateAppFilter: %v", err)
	}

	// Read back via ListMyDevices — the path the console actually uses.
	devs, err := svc.ListMyDevices(context.Background(), uid)
	if err != nil {
		t.Fatalf("ListMyDevices: %v", err)
	}
	if len(devs) != 1 {
		t.Fatalf("expected 1 device, got %d", len(devs))
	}
	d := devs[0]
	if d.AppFilter.Mode != AppFilterInclude {
		t.Errorf("mode: got %q, want %q", d.AppFilter.Mode, AppFilterInclude)
	}
	if !reflect.DeepEqual(d.AppFilter.Packages, []string{"com.acme.app1", "com.acme.app2"}) {
		t.Errorf("packages: got %v, want [com.acme.app1 com.acme.app2]", d.AppFilter.Packages)
	}

	// Switch to off — packages must be wiped server-side.
	err = svc.UpdateAppFilter(context.Background(), reg.Device.ID, uid,
		AppFilterOff, []string{"com.acme.app1"})
	if err != nil {
		t.Fatalf("UpdateAppFilter off: %v", err)
	}
	devs, _ = svc.ListMyDevices(context.Background(), uid)
	if len(devs[0].AppFilter.Packages) != 0 {
		t.Errorf("off mode should wipe packages, got %v", devs[0].AppFilter.Packages)
	}
	if devs[0].AppFilter.Mode != AppFilterOff {
		t.Errorf("mode after off: got %q", devs[0].AppFilter.Mode)
	}
}

func TestUpdateAppFilter_AllocationCarriesFilter_Integration(t *testing.T) {
	db := requireTestDB(t)
	resetDB(t, db)
	uid := seedUser(t, db)
	svc := makeService(t, db)

	// Register, set filter, then call RotateKey: the rotation result
	// should carry the filter so the Android client picks up admin
	// changes on next 12h cycle.
	reg, err := svc.Register(context.Background(), RegisterParams{
		UserID:          uid,
		InstallID:       "44444444-4444-7444-8444-444444444444",
		DisplayName:     "Test Phone 2",
		Platform:        PlatformAndroid,
		DevicePublicKey: randomKey(t),
	})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	err = svc.UpdateAppFilter(context.Background(), reg.Device.ID, uid,
		AppFilterExclude, []string{"com.acme.bypass"})
	if err != nil {
		t.Fatalf("UpdateAppFilter: %v", err)
	}

	// RotateKey to simulate the 12h periodic rotation.
	rot, err := svc.RotateKey(context.Background(), RotateKeyParams{
		DeviceID:           reg.Device.ID,
		NewDevicePublicKey: randomKey(t),
	})
	if err != nil {
		t.Fatalf("RotateKey: %v", err)
	}
	if rot.Allocation.AppFilter.Mode != AppFilterExclude {
		t.Errorf("rotation should snapshot filter mode: got %q", rot.Allocation.AppFilter.Mode)
	}
	if !reflect.DeepEqual(rot.Allocation.AppFilter.Packages, []string{"com.acme.bypass"}) {
		t.Errorf("rotation should snapshot filter packages: got %v", rot.Allocation.AppFilter.Packages)
	}
}
