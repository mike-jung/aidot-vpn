package httpapi

import (
	"context"
	"net/http"
	"strings"
)

// Role-based access control, added in 0.11.0.
//
// Before this, `requireAuth` validated a Keycloak token and stopped
// there. Any account that could sign in to the realm could call
// `POST /policies`, `PUT /policies/{id}/allowed-ips`, and
// `PUT /devices/{id}/policy`. In a hospital deployment where every
// clinician has a realm account, that meant every clinician could widen
// their own device's network access to anything they liked — which makes
// the gateway enforcement added in 0.10.0 pointless, because the policy
// it faithfully enforces was attacker-controlled.
//
// Roles are read from Keycloak's `realm_access.roles` claim. Two exist:
//
//	aidotvpn-admin     manage policies, nodes, and other users' devices
//	aidotvpn-user      register and manage one's own devices (implicit —
//	                   any authenticated account has this)
//
// Deliberately coarse. A finer model (per-tenant admin, read-only
// auditor) is easy to add later; shipping something enforceable now
// matters more than shipping the right taxonomy eventually.

// RoleAdmin is the Keycloak realm role required for administrative
// endpoints.
const RoleAdmin = "aidotvpn-admin"

type rolesCtxKey struct{}

func contextWithRoles(ctx context.Context, roles []string) context.Context {
	return context.WithValue(ctx, rolesCtxKey{}, roles)
}

// rolesFromContext returns the caller's realm roles.
func rolesFromContext(ctx context.Context) []string {
	r, _ := ctx.Value(rolesCtxKey{}).([]string)
	return r
}

// hasRole reports whether the caller holds the named realm role.
func hasRole(ctx context.Context, role string) bool {
	for _, r := range rolesFromContext(ctx) {
		if strings.EqualFold(r, role) {
			return true
		}
	}
	return false
}

// IsAdmin reports whether the request's caller is an AidotVpn admin.
func IsAdmin(ctx context.Context) bool { return hasRole(ctx, RoleAdmin) }

// extractRealmRoles pulls `realm_access.roles` out of a token payload.
//
// Returns nil rather than an error for a token with no roles: an account
// with no realm roles is a valid non-admin user, not a malformed token.
func extractRealmRoles(raw map[string]any) []string {
	realmAccess, ok := raw["realm_access"].(map[string]any)
	if !ok {
		return nil
	}
	list, ok := realmAccess["roles"].([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(list))
	for _, v := range list {
		if s, ok := v.(string); ok && s != "" {
			out = append(out, s)
		}
	}
	return out
}

// requireAdmin wraps a handler so only admins reach it.
//
// Must be composed INSIDE requireAuth — it reads roles the auth
// middleware puts in the context, so on its own it would reject
// everyone. New() applies them in the right order.
func (a *API) requireAdmin(inner http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !IsAdmin(r.Context()) {
			u := userFromContext(r.Context())
			a.cfg.Logger.Info("admin endpoint refused",
				"user", u.Email, "path", r.URL.Path, "roles", rolesFromContext(r.Context()))
			writeError(w, http.StatusForbidden,
				"this action requires the "+RoleAdmin+" role")
			return
		}
		inner.ServeHTTP(w, r.WithContext(r.Context()))
	})
}

// ownsDevice reports whether the caller may act on the given device.
//
// Admins may act on any device in their tenant. Everyone else may act
// only on their own devices.
//
// This closes an inconsistency that existed since Phase 8:
// `updateDeviceAppFilter` checked device ownership but
// `assignDevicePolicy` did not — it validated that the *policy* belonged
// to the caller's tenant and then applied it to whatever device ID was
// in the URL. Two endpoints one line apart in the same file disagreed
// about whether ownership mattered.
func (a *API) ownsDevice(r *http.Request, deviceID interface{ Bytes() []byte }) (bool, error) {
	ctx := r.Context()
	u := userFromContext(ctx)

	if IsAdmin(ctx) {
		// Tenant-scoped, not unrestricted: an admin of tenant A must not
		// reach tenant B's devices.
		var n int
		err := a.cfg.DB.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM devices
			  WHERE id = ? AND tenant_id = ? AND deleted_at IS NULL`,
			deviceID.Bytes(), u.TenantID.Bytes()).Scan(&n)
		if err != nil {
			return false, err
		}
		return n > 0, nil
	}

	var n int
	err := a.cfg.DB.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM devices
		  WHERE id = ? AND user_id = ? AND deleted_at IS NULL`,
		deviceID.Bytes(), u.ID.Bytes()).Scan(&n)
	if err != nil {
		return false, err
	}
	return n > 0, nil
}
