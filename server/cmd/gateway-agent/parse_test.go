package main

import "testing"

// Real `wg show <dev> dump` output, field order from wg(8):
//
//	interface: private-key, public-key, listen-port, fwmark
//	peer:      public-key, preshared-key, endpoint, allowed-ips,
//	           latest-handshake, transfer-rx, transfer-tx, persistent-keepalive
//
// Written from the manual page rather than from our own output, because
// a fixture built from what the code already produces proves only that
// the code agrees with itself.
const dumpFixture = "PRIV=\tPUB=\t51820\toff\n" +
	"sN4rlyov49sQG6eNRVl8kJ0Zx2Qx0mA1cVn0kLbHhVo=\t(none)\t195.230.111.45:52402\t10.78.0.2/32\t1756700000\t4410000\t912000\t25\n" +
	"aB4rlyov49sQG6eNRVl8kJ0Zx2Qx0mA1cVn0kLbHhZz=\t(none)\t(none)\t10.78.0.3/32\t0\t0\t0\toff\n"

func TestPeerFieldsMatchTheManPage(t *testing.T) {
	peers := parseDump(dumpFixture)
	if len(peers) != 2 {
		t.Fatalf("want 2 peers, got %d", len(peers))
	}

	p := peers[0]
	if p.PublicKey != "sN4rlyov49sQG6eNRVl8kJ0Zx2Qx0mA1cVn0kLbHhVo=" {
		t.Errorf("public key: %q", p.PublicKey)
	}
	if p.LastHandshake != 1756700000 {
		t.Errorf("handshake: %d — field 5, not the endpoint or allowed-ips", p.LastHandshake)
	}
	if p.RxBytes != 4410000 || p.TxBytes != 912000 {
		t.Errorf("rx/tx: %d/%d — fields 6 and 7, in that order", p.RxBytes, p.TxBytes)
	}
}

// A peer that has never handshaked reports 0, not an absent line.
//
// That is a real state — registered, never connected — and the console
// shows it differently from idle, so it must survive parsing.
func TestNeverHandshakedIsZeroNotDropped(t *testing.T) {
	peers := parseDump(dumpFixture)
	if len(peers) != 2 {
		t.Fatalf("the never-handshaked peer was dropped")
	}
	if peers[1].LastHandshake != 0 {
		t.Errorf("want 0 for never, got %d", peers[1].LastHandshake)
	}
}

// The first line is the interface, not a peer.
func TestInterfaceLineSkipped(t *testing.T) {
	for _, p := range parseDump(dumpFixture) {
		if p.PublicKey == "PRIV=" || p.PublicKey == "PUB=" {
			t.Fatal("interface line parsed as a peer")
		}
	}
}
