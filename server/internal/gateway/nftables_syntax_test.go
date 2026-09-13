package gateway

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

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
// Skips when nft is unavailable (CI containers, macOS dev machines) so
// this never becomes a flaky gate. `nft -c` is check-only but still needs
// CAP_NET_ADMIN to validate the transaction with the kernel.
func TestRenderedRulesetParsesWithNft(t *testing.T) {
	nft, err := exec.LookPath("nft")
	if err != nil {
		t.Skip("nft not installed; skipping syntax validation")
	}

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
