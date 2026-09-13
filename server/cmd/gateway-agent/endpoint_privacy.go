package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

// Forget where an idle peer was connecting from.
//
// ## What is exposed
//
// `wg show` reports an endpoint per peer — the handset's real public
// address:
//
//	peer: /X3nyLMlOS…
//	endpoint: 195.230.111.45:52402      the phone's carrier or wifi IP
//	latest handshake: 5 hours ago       and it is still there
//
// The kernel holds it because cryptokey routing needs somewhere to send
// packets. That is unavoidable while the peer is talking. What is
// avoidable is that it stays afterwards: the example above is five
// hours idle and the address is still on the interface.
//
// It says where a nurse was — home, a carrier, a café — and anyone with
// a shell on the gateway can read it. Hospital IT, a maintenance
// contractor, anyone who can `docker exec`. The console deliberately
// does not collect this; the interface holds it regardless, so not
// collecting it was never the whole answer.
//
// ## What this does
//
// Removes and immediately re-adds peers whose handshake is older than
// REJECT_AFTER_TIME. The endpoint clears; allowed-ips and the key stay.
// A returning device handshakes again and the endpoint refills.
//
// This is a known WireGuard pattern rather than something invented
// here — the same remove/re-add, on the same 180-second criterion the
// protocol itself uses to decide a session is gone.
//
// ## Cost
//
// A returning peer waits for a handshake before its first packet
// instead of reusing a session that was already dead by definition.
// Hundreds of milliseconds, once.
//
// ## Why 180 seconds
//
// REJECT_AFTER_TIME. Under 120s the session is valid and data flows
// as-is; 120–179s it flows with a handshake interleaved; past 180s a
// handshake is required anyway. So there is nothing to preserve.

const idleCutoffSeconds = 180

// forgetIdleEndpoints clears the endpoint of every peer past the cutoff.
//
// Returns how many were cleared, for the log line — silent maintenance
// that cannot be observed is maintenance nobody trusts.
func forgetIdleEndpoints(device string) (int, error) {
	out, err := exec.Command("wg", "show", device, "dump").Output()
	if err != nil {
		return 0, fmt.Errorf("forgetIdleEndpoints: %w", err)
	}

	now := time.Now().Unix()
	cleared := 0

	for i, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if i == 0 {
			continue // interface line: private-key, public-key, listen-port, fwmark
		}
		// public-key, preshared-key, endpoint, allowed-ips,
		// latest-handshake, transfer-rx, transfer-tx, persistent-keepalive
		f := strings.Split(line, "\t")
		if len(f) < 5 {
			continue
		}
		key, endpoint, allowed, handshake := f[0], f[2], f[3], atoi64(f[4])

		// Nothing to clear, or still inside a live session.
		if endpoint == "" || endpoint == "(none)" {
			continue
		}
		if handshake == 0 || now-handshake <= idleCutoffSeconds {
			continue
		}

		// Remove, then re-add with the same allowed-ips.
		//
		// Two calls rather than one: `wg set` has no way to unset an
		// endpoint, so removing the peer is the only way to drop it.
		// The re-add restores routing; without it the device could not
		// come back.
		if err := exec.Command("wg", "set", device, "peer", key, "remove").Run(); err != nil {
			fmt.Fprintf(os.Stderr, "forget endpoint: remove %s: %v\n", short(key), err)
			continue
		}
		if err := exec.Command("wg", "set", device,
			"peer", key, "allowed-ips", allowed).Run(); err != nil {
			// Worse than leaving the endpoint: the peer is now gone.
			// Loud, because the next peer sync will restore it but an
			// operator should know a device was briefly unroutable.
			fmt.Fprintf(os.Stderr,
				"forget endpoint: FAILED to re-add %s — peer removed: %v\n", short(key), err)
			continue
		}
		cleared++
	}
	return cleared, nil
}

func short(key string) string {
	if len(key) > 10 {
		return key[:10] + "…"
	}
	return key
}
