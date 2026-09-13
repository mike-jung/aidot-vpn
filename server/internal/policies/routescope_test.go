package policies

import "testing"

// RouteScope is the axis that decides what happens to traffic a policy
// does not permit. Getting its fallback wrong in either direction is
// harmful: defaulting to "full" would cut a misconfigured device off the
// network entirely, while treating "full" as "policy" would silently
// re-open the internet on a locked-down clinical handset.
func TestRouteScopeConstants(t *testing.T) {
	if RouteScopePolicy != "policy" {
		t.Errorf("wire value changed: %q", RouteScopePolicy)
	}
	if RouteScopeFull != "full" {
		t.Errorf("wire value changed: %q", RouteScopeFull)
	}
	if RouteScopePolicy == RouteScopeFull {
		t.Fatal("the two scopes must be distinguishable")
	}
}

// The two axes must stay independent. A test that fails here means
// someone collapsed "which apps" and "what happens to non-permitted
// traffic" into one value, which produces a cross-product that grows
// every time either side gains an option.
func TestRouteScopeIsNotAnAppFilterMode(t *testing.T) {
	for _, appMode := range []string{"off", "include", "exclude"} {
		if string(RouteScopePolicy) == appMode || string(RouteScopeFull) == appMode {
			t.Errorf("route scope collides with app filter mode %q", appMode)
		}
	}
}
