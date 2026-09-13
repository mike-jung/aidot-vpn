package httpapi

import (
	"context"
	"encoding/json"
	"testing"
)

func TestExtractRealmRoles(t *testing.T) {
	cases := map[string]struct {
		payload string
		want    []string
	}{
		"keycloak shape": {
			`{"realm_access":{"roles":["offline_access","aidotvpn-admin","uma_authorization"]}}`,
			[]string{"offline_access", "aidotvpn-admin", "uma_authorization"},
		},
		"no realm_access":         {`{"sub":"abc"}`, nil},
		"realm_access wrong type": {`{"realm_access":"nope"}`, nil},
		"roles wrong type":        {`{"realm_access":{"roles":"admin"}}`, nil},
		"empty roles":             {`{"realm_access":{"roles":[]}}`, []string{}},
		"non-string entries dropped": {
			`{"realm_access":{"roles":["ok",42,null,""]}}`,
			[]string{"ok"},
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			var raw map[string]any
			if err := json.Unmarshal([]byte(tc.payload), &raw); err != nil {
				t.Fatalf("bad test payload: %v", err)
			}
			got := extractRealmRoles(raw)
			if len(got) != len(tc.want) {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("got %v, want %v", got, tc.want)
				}
			}
		})
	}
}

// A token with no roles must never be treated as an admin. This is the
// pre-0.11.0 behaviour that RBAC exists to end: every authenticated
// account had full policy control.
func TestPlainUserIsNotAdmin(t *testing.T) {
	ctx := contextWithRoles(context.Background(), []string{"offline_access", "uma_authorization"})
	if IsAdmin(ctx) {
		t.Fatal("an account with only default Keycloak roles must not be an admin")
	}
}

func TestAdminRoleGrantsAdmin(t *testing.T) {
	ctx := contextWithRoles(context.Background(), []string{"aidotvpn-admin"})
	if !IsAdmin(ctx) {
		t.Fatal("aidotvpn-admin must grant admin")
	}
}

// Keycloak role names are configured by hand and case is a common
// source of "why isn't my admin an admin" support tickets.
func TestRoleMatchIsCaseInsensitive(t *testing.T) {
	ctx := contextWithRoles(context.Background(), []string{"AidotVPN-Admin"})
	if !IsAdmin(ctx) {
		t.Fatal("role comparison should be case-insensitive")
	}
}

// A request that never passed through requireAuth has no roles in
// context. Failing closed here matters because requireAdmin is the only
// thing standing between a misrouted handler and policy mutation.
func TestMissingRolesFailsClosed(t *testing.T) {
	if IsAdmin(context.Background()) {
		t.Fatal("a context with no roles must not be admin")
	}
	if hasRole(context.Background(), RoleAdmin) {
		t.Fatal("hasRole must be false on an empty context")
	}
}

func TestSimilarRoleNameIsNotAdmin(t *testing.T) {
	for _, role := range []string{
		"aidotvpn-admins",
		"aidotvpn",
		"admin",
		"not-aidotvpn-admin",
	} {
		ctx := contextWithRoles(context.Background(), []string{role})
		if IsAdmin(ctx) {
			t.Errorf("role %q must not grant admin", role)
		}
	}
}
