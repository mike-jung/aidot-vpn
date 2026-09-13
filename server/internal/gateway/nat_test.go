package gateway

import "testing"

// A policy with source_nat produces a masquerade rule bound to that
// device's tunnel address and that destination — not a blanket one.
//
// The blanket form is what a hand-written setup usually has, and it
// would NAT every destination for every device, silently ending the
// per-device audit trail the console's VPN 주소 column depends on.
func TestNATRuleIsScopedToDeviceAndDestination(t *testing.T) {
	out := Render([]Peer{{
		DeviceID: "d1", PublicKey: "k", IPv4: "10.78.0.2",
		Status: "active", PolicyBound: true,
		DestCIDRs: []string{"192.168.0.12/32", "10.78.0.1/32"},
		NATCIDRs:  []string{"192.168.0.12/32"},
	}}, RenderOptions{WGInterface: "wg0"})

	want := "ip saddr 10.78.0.2 ip daddr 192.168.0.12/32 masquerade"
	if !contains(out, want) {
		t.Fatalf("missing scoped masquerade rule\nwant: %s\ngot:\n%s", want, out)
	}
	// The other destination is reachable and must not be NATed.
	if contains(out, "ip daddr 10.78.0.1/32 masquerade") {
		t.Fatal("NAT applied to a destination the policy did not mark")
	}
}

// No NAT anywhere means an empty chain, not a missing table: the table
// is deleted and recreated every reload, so a policy that stops using
// NAT must actually lose its rule.
func TestNATChainEmptyWhenUnused(t *testing.T) {
	out := Render([]Peer{{
		DeviceID: "d1", PublicKey: "k", IPv4: "10.78.0.2",
		Status: "active", PolicyBound: true,
		DestCIDRs: []string{"10.78.0.1/32"},
	}}, RenderOptions{WGInterface: "wg0"})

	if !contains(out, "table inet aidotvpn_nat") {
		t.Fatal("nat table missing; a stale rule from a previous reload would survive")
	}
	if contains(out, "masquerade") {
		t.Fatal("masquerade rule emitted with no policy asking for it")
	}
}

func contains(hay, needle string) bool {
	return len(hay) >= len(needle) && indexOf(hay, needle) >= 0
}

func indexOf(hay, needle string) int {
	for i := 0; i+len(needle) <= len(hay); i++ {
		if hay[i:i+len(needle)] == needle {
			return i
		}
	}
	return -1
}
