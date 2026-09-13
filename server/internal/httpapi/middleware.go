package httpapi

import (
	"context"
	"errors"
	"github.com/aidotvpn/server/internal/adminauth"
	"github.com/aidotvpn/server/internal/domain"
	"net/http"
	"strings"
)

// requireAuth wraps a handler with session-cookie authentication.
//
// Until 1.8.0 this verified a Keycloak JWT. Keycloak served console login
// only — for a few admins per hospital — and cost a container, a realm
// file, a theme, a sync script and, in one week, six defects that were
// all about matching its rules rather than ours. docs/auth-design-ko.md
// has the reasoning; internal/adminauth has the replacement.
func (a *API) requireAuth(inner http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Session cookie → admin row. One indexed lookup; the token is
		// never stored, only its hash. See internal/adminauth.
		c, err := r.Cookie(SessionCookie)
		if err != nil || c.Value == "" {
			writeError(w, http.StatusUnauthorized, "로그인이 필요합니다")
			return
		}
		admin, err := a.cfg.Admins.Resolve(r.Context(), c.Value)
		if err != nil {
			if !errors.Is(err, adminauth.ErrNoSession) {
				a.serverError(w, "session resolve", err)
				return
			}
			clearSessionCookie(w, r)
			writeError(w, http.StatusUnauthorized, "로그인이 만료되었습니다")
			return
		}
		// The users row is what audit and ownership already key on; keep
		// it, keyed by the admin id where the Keycloak subject used to go.
		u, err := a.cfg.Users.FindOrCreate(r.Context(), admin.TenantID,
			admin.ID.String(), admin.Email, admin.DisplayName)
		if err != nil {
			a.serverError(w, "user upsert", err)
			return
		}
		ctx := contextWithUser(r.Context(), u)
		roles := []string{"aidotvpn-user"}
		if admin.Role == "admin" {
			roles = append(roles, "aidotvpn-admin")
		}
		ctx = contextWithRoles(ctx, roles)
		ctx = context.WithValue(ctx, ctxAdminKey{}, admin)
		ctx = context.WithValue(ctx, ctxSessionTokenKey{}, c.Value)
		inner.ServeHTTP(w, r.WithContext(ctx))
	})
}

type ctxAdminKey struct{}
type ctxSessionTokenKey struct{}

func adminFromContext(ctx context.Context) *adminauth.Admin {
	a, _ := ctx.Value(ctxAdminKey{}).(*adminauth.Admin)
	return a
}
func sessionTokenFromContext(ctx context.Context) string {
	t, _ := ctx.Value(ctxSessionTokenKey{}).(string)
	return t
}

// SessionCookie is the name of the admin session cookie.
const SessionCookie = "aidot_session"

func setSessionCookie(w http.ResponseWriter, r *http.Request, token string) {
	http.SetCookie(w, &http.Cookie{
		Name: SessionCookie, Value: token, Path: "/",
		HttpOnly: true, SameSite: http.SameSiteStrictMode,
		Secure: r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https",
		MaxAge: int(adminauth.AbsoluteTimeout.Seconds()),
	})
}
func clearSessionCookie(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name: SessionCookie, Value: "", Path: "/", HttpOnly: true,
		SameSite: http.SameSiteStrictMode, MaxAge: -1,
	})
}

// requireAuthOrEnrollmentGrant accepts either an OIDC token or a
// one-time enrollment grant.
//
// Only wraps POST /devices/register. A device enrolled by approval has
// no session — that is the whole point of the flow — so it presents the
// grant an admin's approval minted for it.
//
// 1.2.4 shipped this flow with the app sending the grant as a bearer
// and the server verifying it as a JWT. Registration answered:
//
//	401 invalid token: jwt: malformed (expected 3 segments)
//
// I had verified the exchange endpoint and stopped one call short of the
// one that mattered.
//
// The grant is redeemed here, so it is spent whether or not registration
// then succeeds. That is the safe direction: a failed registration can
// be retried by asking an admin again, whereas a grant that survives a
// failure is a credential lying around after the operator has walked
// away.
func (a *API) requireAuthOrEnrollmentGrant(inner http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw := bearerFrom(r)

		// A grant is recognisable and cannot be confused with a JWT,
		// which has dots and no prefix.
		if !strings.HasPrefix(raw, "aidot_") {
			a.requireAuth(inner).ServeHTTP(w, r)
			return
		}

		// Validate without consuming, then consume only on the call that
		// creates the device.
		//
		// 1.2.8 redeemed here, on every route this wraps. Registration is
		// two calls — a challenge, then the register itself — so the
		// grant was spent by the first and the second got 401. Approval
		// worked and the phone still could not finish.
		//
		// Consuming on /devices/register keeps the property that
		// mattered: one grant, one device. A challenge fetched and then
		// abandoned costs nothing.
		consume := r.URL.Path == "/devices/register"

		tenantID, policyID, err := a.cfg.Devices.CheckEnrollmentToken(r.Context(), raw, consume)
		if err != nil {
			writeError(w, http.StatusUnauthorized,
				"등록 허가가 유효하지 않습니다 (만료·폐기되었거나 이미 사용됨)")
			return
		}

		// The device is owned by the approving admin's tenant, with no
		// user — nobody signed in on this handset.
		u, err := a.cfg.Users.FindOrCreate(r.Context(), tenantID,
			"enrolled-device", "", "등록된 기기")
		if err != nil {
			a.serverError(w, "enrollment user upsert", err)
			return
		}

		ctx := contextWithUser(r.Context(), u)
		ctx = contextWithRoles(ctx, nil)
		if policyID != nil {
			ctx = contextWithEnrollmentPolicy(ctx, *policyID)
		}
		inner.ServeHTTP(w, r.WithContext(ctx))
	})
}

type enrollPolicyKey struct{}

// contextWithEnrollmentPolicy carries the policy the grant was issued
// with, so registration can bind it without a second round trip.
func contextWithEnrollmentPolicy(ctx context.Context, id domain.ID) context.Context {
	return context.WithValue(ctx, enrollPolicyKey{}, id)
}

func enrollmentPolicyFrom(ctx context.Context) (domain.ID, bool) {
	id, ok := ctx.Value(enrollPolicyKey{}).(domain.ID)
	return id, ok
}

// bearerFrom returns the token after "Bearer " in the Authorization
// header, case-insensitively. Returns "" if not present.
func bearerFrom(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if h == "" {
		return ""
	}
	const prefix = "bearer "
	if len(h) < len(prefix) || !strings.EqualFold(h[:len(prefix)], prefix) {
		return ""
	}
	return strings.TrimSpace(h[len(prefix):])
}
