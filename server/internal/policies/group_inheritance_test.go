package policies

import (
	"context"
	"database/sql"
	"github.com/aidotvpn/server/internal/domain"
	_ "github.com/go-sql-driver/mysql"
	"os"
	"testing"
)

// Uses the real MariaDB schema and queries; never points at production.
func TestGroupPolicyInheritanceIntegration(t *testing.T) {
	dsn := os.Getenv("AIDOTVPN_TEST_DSN")
	if dsn == "" {
		t.Skip("AIDOTVPN_TEST_DSN not set")
	}
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	tenant, user, dev, group, policy, override := domain.NewID(), domain.NewID(), domain.NewID(), domain.NewID(), domain.NewID(), domain.NewID()
	exec := func(query string, args ...any) {
		t.Helper()
		if _, err := db.ExecContext(ctx, query, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO tenants(id,slug,display_name,ipv4_pool_addr,ipv4_pool_bits) VALUES(?,?,?,INET6_ATON('10.90.0.0'),24)`, tenant.Bytes(), tenant.String(), "QA")
	exec(`INSERT INTO users(id,tenant_id,kc_subject,email) VALUES(?,?,?,?)`, user.Bytes(), tenant.Bytes(), user.String(), "qa@example.invalid")
	for _, id := range []domain.ID{policy, override} {
		exec(`INSERT INTO policies(id,tenant_id,name,route_scope,dns_servers) VALUES(?,?,?,'full','10.10.0.53')`, id.Bytes(), tenant.Bytes(), id.String())
	}
	exec(`INSERT INTO policy_allowed_ips(id,policy_id,cidr) VALUES(?,?,'10.10.0.0/24')`, domain.NewID().Bytes(), policy.Bytes())
	exec(`INSERT INTO device_groups(id,tenant_id,name,policy_id) VALUES(?,?,?,?)`, group.Bytes(), tenant.Bytes(), group.String(), policy.Bytes())
	exec(`INSERT INTO devices(id,tenant_id,user_id,install_id,display_name,group_id) VALUES(?,?,?,?,?,?)`, dev.Bytes(), tenant.Bytes(), user.Bytes(), dev.String(), "QA", group.Bytes())
	defer func() {
		db.Exec(`DELETE FROM devices WHERE id=?`, dev.Bytes())
		db.Exec(`DELETE FROM device_groups WHERE id=?`, group.Bytes())
		db.Exec(`DELETE FROM policy_allowed_ips WHERE policy_id=?`, policy.Bytes())
		db.Exec(`DELETE FROM policies WHERE tenant_id=?`, tenant.Bytes())
		db.Exec(`DELETE FROM users WHERE id=?`, user.Bytes())
		db.Exec(`DELETE FROM tenants WHERE id=?`, tenant.Bytes())
	}()
	svc := &Service{db: db}
	bound, err := svc.IsDeviceBound(ctx, dev)
	if err != nil || !bound {
		t.Fatalf("group bound=%v err=%v", bound, err)
	}
	ips, err := svc.GetEffectiveAllowedIPs(ctx, dev)
	if err != nil || len(ips) != 1 || ips[0] != "10.10.0.0/24" {
		t.Fatalf("group CIDRs=%v err=%v", ips, err)
	}
	dns, err := svc.GetEffectiveDNS(ctx, dev)
	if err != nil || len(dns.Servers) != 1 {
		t.Fatalf("group DNS=%v err=%v", dns, err)
	}
	scope, err := svc.GetEffectiveRouteScope(ctx, dev)
	if err != nil || scope != RouteScopeFull {
		t.Fatalf("scope=%v err=%v", scope, err)
	}
	if _, err := svc.GetEffectiveRules(ctx, dev); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.VirtualHostsForDevice(ctx, dev); err != nil {
		t.Fatal(err)
	}
	exec(`UPDATE devices SET policy_id=? WHERE id=?`, override.Bytes(), dev.Bytes())
	ips, err = svc.GetEffectiveAllowedIPs(ctx, dev)
	if err != nil || len(ips) != 0 {
		t.Fatalf("override merged group CIDRs=%v err=%v", ips, err)
	}
	exec(`UPDATE policies SET enabled=FALSE WHERE id=?`, override.Bytes())
	bound, err = svc.IsDeviceBound(ctx, dev)
	if err != nil || bound {
		t.Fatalf("disabled override fell through to group: %v %v", bound, err)
	}
	exec(`UPDATE devices SET policy_id=NULL WHERE id=?`, dev.Bytes())
	exec(`UPDATE device_groups SET deleted_at=NOW() WHERE id=?`, group.Bytes())
	bound, err = svc.IsDeviceBound(ctx, dev)
	if err != nil || bound {
		t.Fatalf("deleted group still bound: %v %v", bound, err)
	}
}
