package httpapi

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aidotvpn/server/internal/adminauth"
	"github.com/aidotvpn/server/internal/domain"
)

// silentLogger discards output so test logs don't spam the runner.
func silentLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// The middleware must reject at the door without touching downstream
// services. An API with nil services proves it: if the middleware
// leaked through, the nil dereference would panic.
//
// Both cases below need no database: a missing cookie is refused before
// any lookup, and a cookie that does not resolve is refused after the
// lookup — which here is a Service on a nil *sql.DB that we never
// reach for the first case and reach with a token that cannot match
// in the second, where Resolve returns a query error rather than a
// session; the middleware maps that to 500, so we assert only that it
// did not pass. The real resolve path is covered by the e2e login
// check against MariaDB.
func newBareAPI() *API {
	return &API{cfg: Config{Logger: silentLogger(), Admins: adminauth.New(nil), DefaultTenant: domain.NewID()}}
}

func TestRequireAuth_Rejects401_NoCookie(t *testing.T) {
	api := newBareAPI()
	reached := false
	h := api.requireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { reached = true }))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/devices", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	if reached {
		t.Fatal("inner handler reached without a session")
	}
}

func TestRequireAuth_EmptyCookieIsNoSession(t *testing.T) {
	api := newBareAPI()
	reached := false
	h := api.requireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { reached = true }))
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/devices", nil)
	req.AddCookie(&http.Cookie{Name: SessionCookie, Value: ""})
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized || reached {
		t.Fatalf("status = %d reached=%v, want 401 and not reached", rec.Code, reached)
	}
}

func TestParseHexID(t *testing.T) {
	// Round-trip a known UUID: domain.ID's text format includes dashes.
	original := domain.NewID()
	t.Logf("original: %s", original)

	got, err := parseHexID(original.String())
	if err != nil {
		t.Fatalf("parse with dashes: %v", err)
	}
	if got != original {
		t.Errorf("dashed roundtrip mismatch: got %s want %s", got, original)
	}

	// Now strip dashes — should still work via the hex fallback.
	got2, err := parseHexID(original.HexString())
	if err != nil {
		t.Fatalf("parse without dashes: %v", err)
	}
	if got2 != original {
		t.Errorf("hex roundtrip mismatch: got %s want %s", got2, original)
	}

	// And reject obvious garbage.
	if _, err := parseHexID("not-an-id"); err == nil {
		t.Errorf("expected error on garbage input")
	}
}
