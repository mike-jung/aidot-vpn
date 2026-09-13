package attestation

import (
	"math/big"
	"testing"
)

// A compromised batch key's chain verifies against the Google root
// forever. The status list is the only thing that catches it, so an
// unavailable list must not silently mean "clean".
func TestCheckFailsClosedWithNoList(t *testing.T) {
	r := NewRevocation(nil)
	_, _, err := r.Check([]*big.Int{big.NewInt(0x1234)})
	if err == nil {
		t.Fatal("an unfetched status list must not be treated as 'nothing is revoked'")
	}
}

func TestFailOpenIsOptIn(t *testing.T) {
	r := NewRevocation(nil)
	r.FailOpen = true
	if _, _, err := r.Check([]*big.Int{big.NewInt(1)}); err != nil {
		t.Fatalf("FailOpen should admit when the list is unavailable: %v", err)
	}
}

func TestRevokedSerialIsCaught(t *testing.T) {
	r := NewRevocation(nil)
	r.Seed(map[string]StatusEntry{
		"8f2c1b": {Status: "REVOKED", Reason: "KEY_COMPROMISE"},
	})
	serial, ok := new(big.Int).SetString("8f2c1b", 16)
	if !ok {
		t.Fatal("bad test serial")
	}
	got, entry, err := r.Check([]*big.Int{serial})
	if err != nil {
		t.Fatalf("check: %v", err)
	}
	if got == "" {
		t.Fatal("revoked serial was not caught")
	}
	if entry.Reason != "KEY_COMPROMISE" {
		t.Errorf("reason lost: %q", entry.Reason)
	}
}

// Any cert in the chain being revoked invalidates it, not just the leaf —
// a compromised intermediate is the more common real case.
func TestRevokedIntermediateIsCaught(t *testing.T) {
	r := NewRevocation(nil)
	r.Seed(map[string]StatusEntry{"ab": {Status: "REVOKED"}})
	leaf := big.NewInt(0x11)
	intermediate := big.NewInt(0xab)
	got, _, err := r.Check([]*big.Int{leaf, intermediate})
	if err != nil || got == "" {
		t.Fatalf("revoked intermediate must invalidate the chain (got %q, err %v)", got, err)
	}
}

// Google publishes lowercase hex without leading zeros; mirrored lists in
// the wild do both. A formatting mismatch silently reads as "not
// revoked", which is the wrong way to fail.
func TestSerialNormalisation(t *testing.T) {
	r := NewRevocation(nil)
	r.Seed(map[string]StatusEntry{"00AB": {Status: "REVOKED"}})
	got, _, err := r.Check([]*big.Int{big.NewInt(0xab)})
	if err != nil || got == "" {
		t.Fatalf("padded/uppercase serial should still match (got %q, err %v)", got, err)
	}
}

func TestCleanChainPasses(t *testing.T) {
	r := NewRevocation(nil)
	r.Seed(map[string]StatusEntry{"deadbeef": {Status: "REVOKED"}})
	got, _, err := r.Check([]*big.Int{big.NewInt(0x1), big.NewInt(0x2)})
	if err != nil {
		t.Fatalf("check: %v", err)
	}
	if got != "" {
		t.Errorf("clean chain reported as revoked: %q", got)
	}
}
