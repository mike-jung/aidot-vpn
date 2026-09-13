package gateway

import (
	"strings"
	"testing"
)

func TestRenderDefaultsToDrop(t *testing.T) {
	out := Render(nil, RenderOptions{WGInterface: "wg0"})
	if !strings.Contains(out, "policy drop;") {
		t.Fatal("forward chain must default to drop")
	}
	if !strings.Contains(out, "ct state established,related accept") {
		t.Fatal("return traffic must be accepted or every connection hangs")
	}
	if !strings.Contains(out, `delete table inet aidotvpn`) {
		t.Fatal("ruleset must replace the table atomically")
	}
}

// The core regression this whole release exists to prevent: a device the
// admin registered but never assigned a policy to must reach nothing.
// Before 0.10.0 that device got a full tunnel.
func TestUnboundPeerIsDenied(t *testing.T) {
	out := Render([]Peer{{
		DeviceID:    "aabbccddeeff00112233445566778899",
		IPv4:        "10.78.0.5",
		PolicyBound: false,
		DestCIDRs:   []string{"10.10.5.20/32"},
	}}, RenderOptions{WGInterface: "wg0"})

	if !strings.Contains(out, `ip saddr 10.78.0.5/32 drop`) {
		t.Fatalf("unbound peer must be dropped, got:\n%s", out)
	}
	if strings.Contains(out, "10.10.5.20/32 accept") {
		t.Fatal("unbound peer must not get accepts even when CIDRs are present")
	}
}

func TestBoundPeerGetsScopedAccept(t *testing.T) {
	out := Render([]Peer{{
		DeviceID:    "dev1",
		IPv4:        "10.78.0.5",
		PolicyBound: true,
		DestCIDRs:   []string{"10.10.5.20/32", "10.10.5.30/32"},
	}}, RenderOptions{WGInterface: "wg0"})

	for _, want := range []string{
		`iifname "wg0" ip saddr 10.78.0.5/32 ip daddr 10.10.5.20/32 accept`,
		`iifname "wg0" ip saddr 10.78.0.5/32 ip daddr 10.10.5.30/32 accept`,
		`iifname "wg0" drop`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing rule %q in:\n%s", want, out)
		}
	}
	// Nothing else on the hospital LAN may be reachable.
	if strings.Contains(out, "0.0.0.0/0 accept") {
		t.Error("scoped policy must never emit a default-route accept")
	}
}

func TestL4RuleNarrowsPort(t *testing.T) {
	out := Render([]Peer{{
		DeviceID:    "dev1",
		IPv4:        "10.78.0.5",
		PolicyBound: true,
		DestCIDRs:   []string{"10.10.5.20/32"},
		Rules: []Rule{
			{Action: "accept", Dst: "10.10.5.20/32", Protocol: "tcp", PortMin: 443, PortMax: 443},
		},
	}}, RenderOptions{WGInterface: "wg0"})

	if !strings.Contains(out, `ip daddr 10.10.5.20/32 tcp dport 443 accept`) {
		t.Fatalf("expected port-scoped accept, got:\n%s", out)
	}
	// The bare CIDR accept must NOT also be emitted — otherwise the L4
	// rule is decorative and every port stays open.
	if strings.Contains(out, `ip daddr 10.10.5.20/32 accept`) {
		t.Fatalf("L4-covered destination must not also get a bare accept:\n%s", out)
	}
}

func TestPortRangeAndDenyOrdering(t *testing.T) {
	out := Render([]Peer{{
		DeviceID:    "dev1",
		IPv4:        "10.78.0.5",
		PolicyBound: true,
		Rules: []Rule{
			{Action: "drop", Dst: "10.10.5.99/32", Protocol: "any"},
			{Action: "accept", Dst: "10.10.5.0/24", Protocol: "tcp", PortMin: 8000, PortMax: 8100},
		},
	}}, RenderOptions{WGInterface: "wg0"})

	dropIdx := strings.Index(out, "10.10.5.99/32 drop")
	acceptIdx := strings.Index(out, "tcp dport 8000-8100 accept")
	if dropIdx < 0 || acceptIdx < 0 {
		t.Fatalf("both rules must render, got:\n%s", out)
	}
	if dropIdx > acceptIdx {
		t.Error("explicit drop must precede the broader accept or it never matches")
	}
}

func TestUnknownActionIsSkippedNotAccepted(t *testing.T) {
	out := Render([]Peer{{
		DeviceID:    "dev1",
		IPv4:        "10.78.0.5",
		PolicyBound: true,
		Rules:       []Rule{{Action: "allow-ish", Dst: "10.10.5.20/32", Protocol: "any"}},
	}}, RenderOptions{WGInterface: "wg0"})

	if strings.Contains(out, "10.10.5.20/32 allow-ish") ||
		strings.Contains(out, "10.10.5.20/32 accept") {
		t.Fatalf("unrecognised action must be skipped, never widened to accept:\n%s", out)
	}
}

func TestNonTunnelTrafficUntouched(t *testing.T) {
	out := Render(nil, RenderOptions{WGInterface: "wg0"})
	if !strings.Contains(out, `iifname != "wg0" oifname != "wg0" accept`) {
		t.Fatal("the agent must not police traffic unrelated to the tunnel")
	}
}

// Identical input must render byte-identical output, or the agent
// re-applies the ruleset on every poll and churns the kernel.
func TestRenderIsDeterministic(t *testing.T) {
	peers := []Peer{
		{DeviceID: "zzz", IPv4: "10.78.0.9", PolicyBound: true, DestCIDRs: []string{"10.10.5.20/32"}},
		{DeviceID: "aaa", IPv4: "10.78.0.5", PolicyBound: true, DestCIDRs: []string{"10.10.5.30/32"}},
	}
	a := Render(peers, RenderOptions{WGInterface: "wg0"})
	reversed := []Peer{peers[1], peers[0]}
	b := Render(reversed, RenderOptions{WGInterface: "wg0"})
	if a != b {
		t.Error("peer ordering must not change rendered output")
	}
}

func TestIPv6PeerRendersIP6Family(t *testing.T) {
	out := Render([]Peer{{
		DeviceID:    "dev1",
		IPv6:        "fd5e:7c2a:d8e1::5",
		PolicyBound: true,
		DestCIDRs:   []string{"fd00:10::/64"},
	}}, RenderOptions{WGInterface: "wg0"})

	if !strings.Contains(out, "ip6 saddr fd5e:7c2a:d8e1::5/128 ip6 daddr fd00:10::/64 accept") {
		t.Fatalf("v6 peer must render ip6 matches, got:\n%s", out)
	}
}

// A v4 peer must not be cross-matched against a v6 destination (nft would
// reject the ruleset and the agent would fail closed on every reload).
func TestFamilyMismatchIsSkipped(t *testing.T) {
	out := Render([]Peer{{
		DeviceID:    "dev1",
		IPv4:        "10.78.0.5",
		PolicyBound: true,
		DestCIDRs:   []string{"fd00:10::/64"},
	}}, RenderOptions{WGInterface: "wg0"})

	if strings.Contains(out, "saddr 10.78.0.5/32 ip6 daddr") {
		t.Fatalf("must not mix families in one rule:\n%s", out)
	}
}

// A rewrite produces a prerouting dnat rule matched on the device's
// tunnel address and the virtual destination, and the forward chain
// permits the real address — because DNAT runs first, so by the time
// the forward chain sees the packet its destination is already real.
func TestRewriteRendersDNATAndPermitsReal(t *testing.T) {
	rs := Render([]Peer{{
		DeviceID: "d1", IPv4: "10.78.0.2", PolicyBound: true,
		DestCIDRs: []string{"192.168.0.22/32"},
		Rewrites:  []Rewrite{{Virtual: "10.79.0.22", Real: "192.168.0.22"}},
	}}, RenderOptions{})

	want := []string{
		"type nat hook prerouting priority dstnat",
		`iifname "wg0" ip saddr 10.78.0.2 ip daddr 10.79.0.22 dnat to 192.168.0.22`,
		"ip daddr 192.168.0.22/32 accept",
	}
	for _, w := range want {
		if !strings.Contains(rs, w) {
			t.Errorf("ruleset missing %q\n%s", w, rs)
		}
	}
	// The virtual address must NOT appear as a forward accept: nothing
	// should be forwarded to 10.79.0.22, because nothing lives there.
	if strings.Contains(rs, "ip daddr 10.79.0.22/32 accept") {
		t.Errorf("virtual address leaked into the forward chain\n%s", rs)
	}
}

// A virtual destination whose real address is the gateway itself.
//
// The self-contained way to try the feature: no second machine, no
// hospital server. 10.79.0.99 is rewritten to 10.78.0.1, the packet
// lands in the gateway's own INPUT path, and the responder on :8080
// answers. This asserts the dnat rule is rendered for that pair and
// nothing in the forward chain interferes (INPUT is not filtered).
func TestRewriteToGatewaySelf(t *testing.T) {
	rs := Render([]Peer{{
		DeviceID: "d1", IPv4: "10.78.0.2", PolicyBound: true,
		DestCIDRs: []string{"10.78.0.1/32"},
		Rewrites:  []Rewrite{{Virtual: "10.79.0.99", Real: "10.78.0.1"}},
	}}, RenderOptions{})
	if !strings.Contains(rs, `ip saddr 10.78.0.2 ip daddr 10.79.0.99 dnat to 10.78.0.1`) {
		t.Fatalf("no dnat to gateway self\n%s", rs)
	}
	// Gateway-local destinations now require the same ACL as forwarded ones.
	inputStart := strings.Index(rs, "chain input")
	forwardStart := strings.Index(rs, "chain forward")
	if inputStart < 0 || forwardStart < inputStart || !strings.Contains(rs[inputStart:forwardStart], `ip saddr 10.78.0.2/32 ip daddr 10.78.0.1/32 accept`) {
		t.Fatalf("policy-authorized DNAT to gateway must pass INPUT\n%s", rs)
	}
}

func TestClientEstablishedTrafficStillChecksPolicy(t *testing.T) {
	out := Render(nil, RenderOptions{})
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "ct state established,related accept") && !strings.Contains(line, `iifname != "wg0" oifname "wg0"`) {
			t.Fatalf("client traffic bypasses policy: %s", line)
		}
	}
}
func TestProtocolWithoutPortUsesMeta(t *testing.T) {
	for _, protocol := range []string{"tcp", "udp"} {
		if got := l4Match(Rule{Protocol: protocol}); got != " meta l4proto "+protocol {
			t.Fatalf("invalid no-port match %q", got)
		}
	}
}

func TestBroadCIDRCannotBypassNarrowPortRule(t *testing.T) {
	out := Render([]Peer{{DeviceID: "test", IPv4: "10.78.0.2", PolicyBound: true, DestCIDRs: []string{"10.10.0.0/16"}, Rules: []Rule{{Action: "accept", Dst: "10.10.1.2/32", Protocol: "tcp", PortMin: 443, PortMax: 443}}}}, RenderOptions{})
	allow := strings.Index(out, "tcp dport 443 accept")
	guard := strings.Index(out, "ip daddr 10.10.1.2/32 drop")
	broad := strings.Index(out, "ip daddr 10.10.0.0/16 accept")
	if allow < 0 || guard < allow || broad < guard {
		t.Fatal("broad CIDR bypasses the port restriction")
	}
}

func TestGatewayLocalServicesArePolicyFiltered(t *testing.T) {
	out := Render(nil, RenderOptions{})
	start := strings.Index(out, "chain input {")
	end := strings.Index(out, "chain forward {")
	if start < 0 || end < start || !strings.Contains(out[start:end], `iifname "wg0" drop`) {
		t.Fatal("local gateway services bypass policy")
	}
}
