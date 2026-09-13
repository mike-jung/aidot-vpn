package policies

import (
	"net/netip"
	"testing"
)

// The guard is what keeps hostname policies from turning DNS control into
// ACL control. Without it, whoever can answer for `emr.hospital.local`
// decides what the gateway permits.
func TestGuardRejectsOutsideRange(t *testing.T) {
	guard := netip.MustParsePrefix("10.10.0.0/16")

	cases := map[string]bool{
		"10.10.5.20":  true,  // inside
		"10.10.255.1": true,  // inside, edge
		"10.11.0.1":   false, // outside — adjacent range
		"8.8.8.8":     false, // outside — public
		"127.0.0.1":   false, // outside — loopback
	}
	for addr, want := range cases {
		got := guard.Contains(netip.MustParseAddr(addr))
		if got != want {
			t.Errorf("guard.Contains(%s) = %v, want %v", addr, got, want)
		}
	}
}

// A v6 answer must not accidentally satisfy a v4 guard, or a resolver
// returning AAAA records would bypass the range check entirely.
func TestGuardIsFamilyAware(t *testing.T) {
	v4Guard := netip.MustParsePrefix("10.10.0.0/16")
	v6 := netip.MustParseAddr("fd00:10::5")
	if v4Guard.Contains(v6) {
		t.Fatal("a v4 guard must not admit a v6 address")
	}

	v6Guard := netip.MustParsePrefix("fd00:10::/64")
	if !v6Guard.Contains(v6) {
		t.Fatal("a v6 guard should admit an in-range v6 address")
	}
	if v6Guard.Contains(netip.MustParseAddr("10.10.5.20")) {
		t.Fatal("a v6 guard must not admit a v4 address")
	}
}

// IPv4-mapped v6 answers (::ffff:10.10.5.20) must compare as v4, or an
// in-range address gets rejected and a legitimate server becomes
// unreachable. The resolver calls Unmap() for this reason.
func TestMappedV4IsUnmappedBeforeGuardCheck(t *testing.T) {
	guard := netip.MustParsePrefix("10.10.0.0/16")
	mapped := netip.MustParseAddr("::ffff:10.10.5.20")

	if guard.Contains(mapped) {
		t.Fatal("precondition: a mapped address should not match a v4 prefix directly")
	}
	if !guard.Contains(mapped.Unmap()) {
		t.Fatal("after Unmap the address must fall inside the guard")
	}
}

func TestDedupe(t *testing.T) {
	in := []string{"10.10.5.20/32", "10.10.5.30/32", "10.10.5.20/32", "10.10.5.20/32"}
	out := dedupe(in)
	if len(out) != 2 {
		t.Fatalf("dedupe = %v, want 2 entries", out)
	}
	// Order must survive: the client's AllowedIPs list is compared
	// against the previous one to decide whether to rebind the tunnel,
	// and a reordering would look like a change.
	if out[0] != "10.10.5.20/32" || out[1] != "10.10.5.30/32" {
		t.Errorf("order not preserved: %v", out)
	}
}

func TestDedupeShortInputs(t *testing.T) {
	if got := dedupe(nil); got != nil {
		t.Errorf("nil in, %v out", got)
	}
	if got := dedupe([]string{"a"}); len(got) != 1 {
		t.Errorf("single element mangled: %v", got)
	}
}

func TestSplitList(t *testing.T) {
	cases := map[string][]string{
		"":                     nil,
		"   ":                  nil,
		"10.10.1.1":            {"10.10.1.1"},
		"10.10.1.1, 10.10.1.2": {"10.10.1.1", "10.10.1.2"},
		" a ,, b , ":           {"a", "b"},
	}
	for in, want := range cases {
		got := splitList(in)
		if len(got) != len(want) {
			t.Errorf("splitList(%q) = %v, want %v", in, got, want)
			continue
		}
		for i := range got {
			if got[i] != want[i] {
				t.Errorf("splitList(%q) = %v, want %v", in, got, want)
				break
			}
		}
	}
}

// A hostname resolving to an address a static CIDR already covers must
// not produce a duplicate entry, or the client rebinds its tunnel on
// every refresh for no reason.
func TestNormalisationMakesEquivalentCIDRsCollide(t *testing.T) {
	a, err := normalizeCIDR("10.10.5.20/32")
	if err != nil {
		t.Fatal(err)
	}
	b, err := normalizeCIDR("10.10.5.20/32")
	if err != nil {
		t.Fatal(err)
	}
	if a != b {
		t.Fatalf("%q != %q", a, b)
	}
	if got := dedupe([]string{a, b}); len(got) != 1 {
		t.Errorf("equivalent CIDRs did not collapse: %v", got)
	}
}
