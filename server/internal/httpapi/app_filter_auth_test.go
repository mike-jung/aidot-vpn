package httpapi

import (
	"database/sql"
	"encoding/json"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/aidotvpn/server/internal/audit"
	"github.com/aidotvpn/server/internal/auth"
	"github.com/aidotvpn/server/internal/devices"
	"github.com/aidotvpn/server/internal/domain"
	"github.com/aidotvpn/server/internal/users"
	_ "github.com/go-sql-driver/mysql"
)

// Run against a disposable, migrated test database, never the live database.
func TestAppFilterAuthorizationIntegration(t *testing.T) {
	dsn := os.Getenv("AIDOTVPN_TEST_DSN")
	if dsn == "" {
		t.Skip("AIDOTVPN_TEST_DSN required")
	}
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	exec := func(query string, args ...any) {
		t.Helper()
		if _, err := db.Exec(query, args...); err != nil {
			t.Fatal(err)
		}
	}
	tenants := []domain.ID{domain.NewID(), domain.NewID()}
	for _, id := range tenants {
		exec(`INSERT INTO tenants (id,slug,display_name,ipv4_pool_addr,ipv4_pool_bits) VALUES (?,?,?,INET6_ATON('10.99.0.0'),16)`, id.Bytes(), id.String(), "app-filter test")
	}
	owner, admin, other, foreign := domain.NewID(), domain.NewID(), domain.NewID(), domain.NewID()
	for _, row := range []struct{ id, tenant domain.ID }{{owner, tenants[0]}, {admin, tenants[0]}, {other, tenants[0]}, {foreign, tenants[1]}} {
		exec(`INSERT INTO users (id,tenant_id,kc_subject,email) VALUES (?,?,?,?)`, row.id.Bytes(), row.tenant.Bytes(), row.id.String(), row.id.String()+"@example.test")
	}
	did, foreignDevice, deleted, legacy := domain.NewID(), domain.NewID(), domain.NewID(), domain.NewID()
	for _, row := range []struct{ id, tenant, user domain.ID }{{did, tenants[0], owner}, {foreignDevice, tenants[1], foreign}, {deleted, tenants[0], owner}, {legacy, tenants[0], owner}} {
		exec(`INSERT INTO devices (id,tenant_id,user_id,install_id,display_name,platform,status,os_version,app_version) VALUES (?,?,?,?,?,'android','active','','')`, row.id.Bytes(), row.tenant.Bytes(), row.user.Bytes(), row.id.String(), "filter authorization test")
	}
	exec(`UPDATE devices SET deleted_at=NOW() WHERE id=?`, deleted.Bytes())
	exec(`UPDATE devices SET os_version=NULL, app_version=NULL WHERE id=?`, legacy.Bytes())
	ca, err := auth.NewCA(auth.CAOptions{CommonName: "app-filter-test"})
	if err != nil {
		t.Fatal(err)
	}
	svc, err := devices.New(devices.Config{DB: db, CA: ca, Audit: audit.New(db), TenantID: tenants[0]})
	if err != nil {
		t.Fatal(err)
	}
	a := newBareAPI()
	a.cfg.DB, a.cfg.Devices = db, svc
	for _, tc := range []struct {
		name                 string
		user, tenant, device domain.ID
		admin                bool
		body                 string
		want                 int
	}{
		{"admin_other_owner_same_tenant", admin, tenants[0], did, true, `{"mode":"include","packages":["com.aidotvpn.demo"]}`, 200},
		{"owner_allowed", owner, tenants[0], did, false, `{"mode":"exclude","packages":["com.example.excluded"]}`, 200},
		{"ordinary_other_owner_denied", other, tenants[0], did, false, `{"mode":"off","packages":[]}`, 404},
		{"admin_other_tenant_denied", admin, tenants[0], foreignDevice, true, `{"mode":"include","packages":["com.example.invalid"]}`, 404},
		{"foreign_admin_denied", foreign, tenants[1], did, true, `{"mode":"off","packages":[]}`, 404},
		{"deleted_device_denied", admin, tenants[0], deleted, true, `{"mode":"off","packages":[]}`, 404},
		{"missing_device_denied", admin, tenants[0], domain.NewID(), true, `{"mode":"off","packages":[]}`, 404},
		{"invalid_mode_rejected", admin, tenants[0], did, true, `{"mode":"invalid","packages":[]}`, 400},
		{"admin_can_restore_off", admin, tenants[0], did, true, `{"mode":"off","packages":["com.aidotvpn.demo"]}`, 200},
		{"nullable_legacy_metadata", admin, tenants[0], legacy, true, `{"mode":"include","packages":["com.aidotvpn.demo"]}`, 200},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before, err := svc.Get(t.Context(), tc.device)
			if err != nil && tc.want != 404 {
				t.Fatal(err)
			}
			r := httptest.NewRequest("PUT", "/devices/"+tc.device.String()+"/app-filter", strings.NewReader(tc.body))
			r.SetPathValue("id", tc.device.String())
			ctx := contextWithUser(r.Context(), &users.User{ID: tc.user, TenantID: tc.tenant})
			if tc.admin {
				ctx = contextWithRoles(ctx, []string{RoleAdmin})
			}
			w := httptest.NewRecorder()
			a.updateDeviceAppFilter(w, r.WithContext(ctx))
			if w.Code != tc.want {
				t.Fatalf("status=%d want=%d body=%s", w.Code, tc.want, w.Body.String())
			}
			after, _ := svc.Get(t.Context(), tc.device)
			if tc.want != 200 {
				if before != nil && after != nil {
					b, _ := json.Marshal(before.AppFilter)
					v, _ := json.Marshal(after.AppFilter)
					if string(b) != string(v) {
						t.Fatal("rejected request changed stored filter")
					}
				}
				return
			}
			var response deviceJSON
			if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
				t.Fatal(err)
			}
			if response.ID != tc.device.String() || response.AppFilterMode != string(after.AppFilter.Mode) {
				t.Fatal("response does not contain updated device")
			}
			if response.AppFilterMode == "off" && len(response.AppFilterPackages) != 0 {
				t.Fatal("off must clear package list")
			}
		})
	}
}
