package gateway

import (
	"context"
	"log/slog"
	"os"
	"strings"
	"testing"
)

// The phone mixes its PSK into every handshake. If the gateway does not
// hold the same key, the response it sends cannot be opened, and the
// phone logs "Received invalid response message" once per attempt —
// which is what happened for twenty-two attempts on 2026-09-02.
//
// So: a peer that arrives with a PSK must be applied with
// `preshared-key <file>`, the file must hold the key, the file must be
// gone afterwards, and a second sync with the same peer must not
// re-issue the command.
// runnerFn adapts a closure to CommandRunner.
type runnerFn func(ctx context.Context, name string, args []string, stdin string) (string, error)

func (f runnerFn) Run(ctx context.Context, name string, args []string, stdin string) (string, error) {
	return f(ctx, name, args, stdin)
}

func TestApplyPeersPassesPSKViaFile(t *testing.T) {
	var calls [][]string
	var pskSeen string
	dump := "priv\tpub\t52840\toff\n" // header line; no peers yet
	r := runnerFn(func(_ context.Context, name string, args []string, _ string) (string, error) {
		calls = append(calls, append([]string{name}, args...))
		if name == "wg" && len(args) >= 2 && args[0] == "show" {
			return dump, nil
		}
		if name == "wg" && args[0] == "set" {
			for i, a := range args {
				if a == "preshared-key" && i+1 < len(args) {
					b, err := os.ReadFile(args[i+1])
					if err != nil {
						t.Fatalf("psk file unreadable during wg set: %v", err)
					}
					pskSeen = strings.TrimSpace(string(b))
					// After this call the syncer removes the file; note
					// the name so we can check.
					dump = "priv\tpub\t52840\toff\n" +
						"PUB1\t" + pskSeen + "\t(none)\t10.78.0.2/32\t0\t0\t0\t25\n"
				}
			}
		}
		return "", nil
	})
	s := &Syncer{Runner: r, WGInterface: "wg0", Logger: slog.Default(), lastPeerSet: map[string]string{}}

	peer := Peer{PublicKey: "PUB1", PSK: "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG=", IPv4: "10.78.0.2", PolicyBound: true}
	if err := s.applyPeers(context.Background(), []Peer{peer}); err != nil {
		t.Fatal(err)
	}

	if pskSeen != peer.PSK {
		t.Fatalf("wg set received PSK %q, want %q", pskSeen, peer.PSK)
	}
	var pskFile string
	for _, c := range calls {
		for i, a := range c {
			if a == "preshared-key" {
				pskFile = c[i+1]
			}
		}
	}
	if pskFile == "" {
		t.Fatal("wg set was never given preshared-key")
	}
	if _, err := os.Stat(pskFile); err == nil {
		t.Fatalf("psk file %s still exists after apply", pskFile)
	}

	// Same peer again: the kernel now reports the PSK, so nothing to do.
	n := len(calls)
	if err := s.applyPeers(context.Background(), []Peer{peer}); err != nil {
		t.Fatal(err)
	}
	for _, c := range calls[n:] {
		if c[0] == "wg" && c[1] == "set" {
			t.Fatalf("unchanged peer was re-applied: %v", c)
		}
	}
}

func TestApplyPeersClearsRemovedPSK(t *testing.T) {
	cleared := false
	s := &Syncer{WGInterface: "wg0", Logger: slog.Default()}
	s.Runner = runnerFn(func(_ context.Context, name string, args []string, _ string) (string, error) {
		if args[0] == "show" {
			return "priv\tpub\t0\toff\nPUB1\tOLDKEY\t(none)\t10.78.0.2/32\t0\t0\t0\t25\n", nil
		}
		for i, arg := range args {
			if arg == "preshared-key" && i+1 < len(args) {
				data, err := os.ReadFile(args[i+1])
				if err != nil {
					t.Fatal(err)
				}
				cleared = len(data) == 0
			}
		}
		return "", nil
	})
	if err := s.applyPeers(context.Background(), []Peer{{PublicKey: "PUB1", IPv4: "10.78.0.2"}}); err != nil {
		t.Fatal(err)
	}
	if !cleared {
		t.Fatal("old PSK was retained")
	}
}
