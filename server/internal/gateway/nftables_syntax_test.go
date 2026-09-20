package gateway

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// requireNftEnv is set where the nft syntax check must actually run. A host
// that cannot run it then fails the test instead of skipping it, so a CI
// runner that quietly loses nft or its privileges is noticed. The Public
// validation workflow sets it for the step that runs this test as root.
const requireNftEnv = "AIDOTVPN_TEST_REQUIRE_NFT"

// TestRenderedRulesetParsesWithNft runs the real nftables parser over our
// generated ruleset.
//
// Unit tests that only grep for substrings can pass while emitting a
// ruleset nft refuses to load — and a gateway that fails to apply its
// ruleset either keeps a stale policy or, worse, has no table at all and
// falls back to the host's default forward policy. Checking against the
// actual parser is the only way to catch a syntax regression before it
// reaches a hospital.
//
// Skips when nft cannot validate anything on this host (no nft binary, or
// nft without CAP_NET_ADMIN) so this never becomes a flaky gate; see
// nftForSyntaxCheck. Set AIDOTVPN_TEST_REQUIRE_NFT=1 where a skip must be
// treated as a failure.
func TestRenderedRulesetParsesWithNft(t *testing.T) {
	nft := nftForSyntaxCheck(t)

	cases := map[string][]Peer{
		"empty": nil,
		"mixed": {
			{
				DeviceID: "01965abc0000700080000000000000a1", IPv4: "10.78.0.5",
				PolicyBound: true,
				DestCIDRs:   []string{"10.10.5.20/32", "10.10.5.30/32"},
				Rules: []Rule{
					{Action: "accept", Dst: "10.10.5.20/32", Protocol: "tcp", PortMin: 443, PortMax: 443},
					{Action: "drop", Dst: "10.10.5.99/32", Protocol: "any"},
					{Action: "accept", Dst: "10.10.6.0/24", Protocol: "udp", PortMin: 5000, PortMax: 5100},
				},
			},
			{DeviceID: "unbound-device", IPv4: "10.78.0.6", PolicyBound: false},
			{
				DeviceID: "v6-device", IPv6: "fd5e:7c2a:d8e1::5",
				PolicyBound: true,
				DestCIDRs:   []string{"fd00:10::/64"},
				Rules: []Rule{
					{Action: "accept", Dst: "fd00:10::/64", Protocol: "icmpv6"},
				},
			},
			{DeviceID: "no-address", PolicyBound: true, DestCIDRs: []string{"10.10.5.20/32"}},
		},
	}

	for name, peers := range cases {
		t.Run(name, func(t *testing.T) {
			for _, logDenied := range []bool{false, true} {
				script := Render(peers, RenderOptions{
					WGInterface: "wg0",
					LogDenied:   logDenied,
				})
				path := filepath.Join(t.TempDir(), "ruleset.nft")
				if err := os.WriteFile(path, []byte(script), 0o600); err != nil {
					t.Fatalf("write ruleset: %v", err)
				}
				// -c is check-only: parse and validate, never commit.
				out, err := exec.Command(nft, "-c", "-f", path).CombinedOutput()
				if err != nil {
					t.Fatalf("nft rejected ruleset (log_denied=%v): %v\n%s\n--- ruleset ---\n%s",
						logDenied, err, out, script)
				}
			}
		})
	}
}

// nftForSyntaxCheck returns the nft binary to validate with, after proving
// that it can validate a ruleset on this host at all.
//
// Having nft on PATH is not enough. `nft -c` never commits, but even a
// check-only run opens an nf_tables netlink socket to load the kernel's
// cache, and that needs CAP_NET_ADMIN. GitHub-hosted Ubuntu runners ship
// nft and run jobs as an unprivileged user, so a PATH lookup said
// "available" while every invocation failed with
//
//	netlink: Error: cache initialization failed: Operation not permitted
//
// which is a fact about the runner, not about our ruleset. The probe is a
// trivially valid file in the same shape as the real ruleset's opening
// lines; if nft rejects it, this host cannot tell a good ruleset from a bad
// one and the test is skipped — or fails, when AIDOTVPN_TEST_REQUIRE_NFT
// says a skip is not acceptable here.
func nftForSyntaxCheck(t *testing.T) string {
	t.Helper()
	unavailable := func(format string, args ...any) {
		t.Helper()
		if os.Getenv(requireNftEnv) != "" {
			t.Fatalf(requireNftEnv+" is set, but "+format, args...)
		}
		t.Skipf(format, args...)
	}

	nft, err := exec.LookPath("nft")
	if err != nil {
		unavailable("nft is not installed on this host, so the ruleset cannot be checked against the real parser")
	}

	probe := filepath.Join(t.TempDir(), "probe.nft")
	script := "table inet aidotvpn_probe {}\ndelete table inet aidotvpn_probe\n"
	if err := os.WriteFile(probe, []byte(script), 0o600); err != nil {
		t.Fatalf("write probe ruleset: %v", err)
	}
	if out, err := exec.Command(nft, "-c", "-f", probe).CombinedOutput(); err != nil {
		unavailable("nft cannot validate rulesets on this host; a check-only run still needs CAP_NET_ADMIN to read the nf_tables cache: %v\n%s",
			err, out)
	}
	return nft
}
