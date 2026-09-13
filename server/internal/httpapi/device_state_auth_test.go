package httpapi

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"github.com/aidotvpn/server/internal/audit"
	"github.com/aidotvpn/server/internal/auth"
	"github.com/aidotvpn/server/internal/devices"
	"github.com/aidotvpn/server/internal/domain"
	"github.com/aidotvpn/server/internal/policies"
	_ "github.com/go-sql-driver/mysql"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func TestStateAuthMissingAndMalformed(t *testing.T) {
	api := newBareAPI()
	for _, header := range []string{"", "Bearer", "Bearer short", "Basic abc", "Bearer " + string(make([]byte, 43))} {
		r := httptest.NewRequest("GET", "/devices/id/state", nil)
		r.SetPathValue("id", domain.NewID().String())
		if header != "" {
			r.Header.Set("Authorization", header)
		}
		w := httptest.NewRecorder()
		api.requireDeviceStateAuth(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("unauthorized handler invoked") })).ServeHTTP(w, r)
		if w.Code != 401 || w.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("status %d", w.Code)
		}
	}
}

func TestStateAuthLifecycleIntegration(t *testing.T) {
	dsn := os.Getenv("AIDOTVPN_TEST_DSN")
	if dsn == "" {
		t.Skip("AIDOTVPN_TEST_DSN required")
	}
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	tenant, _ := domain.ParseID("019650000000700080000000000000A1")
	uid := domain.NewID()
	_, err = db.Exec(`INSERT INTO users (id,tenant_id,kc_subject,email,display_name) VALUES (?,?,?,?,?)`, uid.Bytes(), tenant.Bytes(), uid.String(), uid.String()+"@example.test", "state auth test")
	if err != nil {
		t.Fatal(err)
	}
	ca, err := auth.NewCA(auth.CAOptions{CommonName: "state-test"})
	if err != nil {
		t.Fatal(err)
	}
	svc, err := devices.New(devices.Config{DB: db, CA: ca, Audit: audit.New(db), TenantID: tenant})
	if err != nil {
		t.Fatal(err)
	}
	pub := make([]byte, 32)
	rand.Read(pub)
	params := devices.RegisterParams{UserID: uid, InstallID: domain.NewID().String(), DisplayName: "state test", Platform: devices.PlatformAndroid, DevicePublicKey: pub, AttestationToken: "stub"}
	registration, err := svc.Register(context.Background(), params)
	if err != nil {
		t.Fatal(err)
	}
	token := registration.Allocation.StateToken
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil || len(raw) != 32 {
		t.Fatal("invalid issued token")
	}
	var stored []byte
	if err = db.QueryRow("SELECT token_hash FROM device_state_tokens WHERE device_id=?", registration.Device.ID.Bytes()).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte(token))
	if string(stored) != string(digest[:]) {
		t.Fatal("credential is not stored as hash")
	}
	api := newBareAPI()
	api.cfg.DB = db
	api.cfg.Devices = svc
	mux := http.NewServeMux()
	mux.Handle("GET /devices/{id}/state", api.requireDeviceStateAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) })))
	server := httptest.NewServer(mux)
	defer server.Close()
	call := func(id, token string, want int) {
		t.Helper()
		r, _ := http.NewRequest("GET", server.URL+"/devices/"+id+"/state", nil)
		if token != "" {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		resp, e := server.Client().Do(r)
		if e != nil {
			t.Fatal(e)
		}
		defer resp.Body.Close()
		if resp.StatusCode != want {
			t.Fatalf("want %d got %d", want, resp.StatusCode)
		}
	}
	id := registration.Device.ID.String()
	call(id, "", 401)
	call(id, token, 204)
	call(domain.NewID().String(), token, 401)
	secondParams := params
	secondParams.InstallID = domain.NewID().String()
	secondParams.DevicePublicKey = make([]byte, 32)
	rand.Read(secondParams.DevicePublicKey)
	second, err := svc.Register(context.Background(), secondParams)
	if err != nil {
		t.Fatal(err)
	}
	call(second.Device.ID.String(), token, 401)
	call(id, second.Allocation.StateToken, 401)
	call(second.Device.ID.String(), second.Allocation.StateToken, 204)

	bad := make([]byte, 32)
	rand.Read(bad)
	call(id, base64.RawURLEncoding.EncodeToString(bad), 401)
	// WireGuard key rotation does not accidentally invalidate the REST credential.
	nextKey := make([]byte, 32)
	rand.Read(nextKey)
	if _, e := svc.RotateKey(context.Background(), devices.RotateKeyParams{DeviceID: registration.Device.ID, NewDevicePublicKey: nextKey}); e != nil {
		t.Fatal(e)
	}
	call(id, token, 204)
	// Re-registration rotates the read credential atomically, invalidating the old one.
	rand.Read(params.DevicePublicKey)
	registration, err = svc.Register(context.Background(), params)
	if err != nil {
		t.Fatal(err)
	}
	call(id, token, 401)
	token = registration.Allocation.StateToken
	call(id, token, 204)
	// Exercise the real policy response as well as the authorization gate.
	policyService, e := policies.New(db, audit.New(db))
	if e != nil {
		t.Fatal(e)
	}
	api.cfg.Policies = policyService
	activeMux := http.NewServeMux()
	api.registerDeviceStateRoute(activeMux)
	activeW := httptest.NewRecorder()
	activeR := httptest.NewRequest("GET", "/devices/"+id+"/state", nil)
	activeR.Header.Set("Authorization", "Bearer "+token)
	activeMux.ServeHTTP(activeW, activeR)
	if activeW.Code != 200 {
		t.Fatalf("active state: %d %s", activeW.Code, activeW.Body.String())
	}
	var active map[string]any
	json.Unmarshal(activeW.Body.Bytes(), &active)
	if active["status"] != "active" || active["allowed_ips"] == nil {
		t.Fatal("missing active policy response")
	}
	if _, ok := active["state_token"]; ok {
		t.Fatal("state response must not echo credential")
	}
	// The real endpoint returns only status after revocation, without policy metadata.
	if _, err = db.Exec("UPDATE devices SET status='revoked' WHERE id=?", registration.Device.ID.Bytes()); err != nil {
		t.Fatal(err)
	}
	realMux := http.NewServeMux()
	api.registerDeviceStateRoute(realMux)
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/devices/"+id+"/state", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	realMux.ServeHTTP(w, r)
	var result map[string]any
	json.Unmarshal(w.Body.Bytes(), &result)
	if w.Code != 200 || result["status"] != "revoked" || result["policy_bound"] != false || len(result) != 2 {
		t.Fatalf("revoked response must be minimal: %d %s", w.Code, w.Body.String())
	}
	db.Close()
	call(id, token, 500)

}

func TestStateCredentialInRegistrationAllocation(t *testing.T) {
	view := allocationJSON(&devices.Allocation{StateToken: "test-only"}, nil, false, "policy", policies.DNSSettings{}, "", "", "")
	if view["state_token"] != "test-only" {
		t.Fatal("registration allocation lost state credential")
	}
}
