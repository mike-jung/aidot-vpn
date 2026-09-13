package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// Tell the controller what this gateway is actually running.
//
// The agent polled for peers and said nothing back, so `nodes` held a
// row that read 활성 whether or not WireGuard was up. A handset
// connected, showed the key icon and reached nothing, while the console
// reported the node healthy — because the row and the process were
// never connected.
//
// Two facts go up, and both are things only the gateway knows:
//
//   wg_interface_up  — whether `wg show <dev>` returns anything
//   wg_backend       — kernel module or wireguard-go
//
// The second is here because wg-quick falls back silently. Both carry
// traffic and one is several times slower, so "why is this slow" ends
// in `docker compose logs` unless the answer is on the dashboard.

type nodeReport struct {
	WGBackend     string      `json:"wg_backend"`
	WGInterfaceUp bool        `json:"wg_interface_up"`
	PeerCount     int         `json:"peer_count"`
	AgentVersion  string      `json:"agent_version"`
	Peers         []peerState `json:"peers"`

	// Whether the responder on the tunnel address is up. The agent
	// shares the gateway's network namespace, so /run/responder-ready
	// is the file the responder wrote after binding both ports. Absent
	// means an image from before 1.7.31 or a responder that died —
	// either way 10.78.0.1:8080 will not answer, and the console should
	// say so before a phone finds out.
	ResponderUp bool `json:"responder_up"`
}

// One row of `wg show <dev> dump`, for the fields the console needs.
type peerState struct {
	PublicKey     string `json:"public_key"`
	LastHandshake int64  `json:"last_handshake"`
	// Where the peer's packets came from — the phone's public
	// address:port as the gateway saw it. Tailscale shows this as the
	// device's public IP; for a nurse on hospital Wi-Fi it is the
	// hospital's NAT address, for one on LTE it is the carrier's. "(none)"
	// from wg means no packet has arrived yet.
	Endpoint string `json:"endpoint,omitempty"`
	RxBytes  int64  `json:"rx_bytes"`
	TxBytes  int64  `json:"tx_bytes"`

	// Whether this peer arrived through the relay.
	//
	// A phone on hotel wifi that blocks UDP connects over the relay
	// instead, and nothing showed which ones did — so "why is only this
	// phone slow" had no answer in the console.
	//
	// Decided by the endpoint's source address: relayed traffic reaches
	// the gateway from the relay process rather than from the handset,
	// so the endpoint is the relay's. That is the only signal available
	// here — the gateway sees packets, not how they were wrapped.
	ViaRelay bool `json:"via_relay"`
}

// peerStates parses `wg show <dev> dump`.
//
// The dump format is stable and tab-separated, which is why it is used
// here rather than the human-readable output: one line per peer, with
// the interface on the first line.
//
//	pubkey  psk  endpoint  allowed-ips  latest-handshake  rx  tx  keepalive
//
// A handshake of 0 means the peer has never completed one — a device
// that registered and never connected. That is a real state and the
// console distinguishes it, so it is passed through rather than
// filtered here.
func peerStates(device string) []peerState {
	out, err := exec.Command("wg", "show", device, "dump").Output()
	if err != nil {
		return nil
	}
	return parseDump(string(out))
}

// parseDump is split out so the field order can be tested against the
// man page without a WireGuard interface present.
func parseDump(out string) []peerState {
	var peers []peerState
	for i, line := range strings.Split(strings.TrimSpace(out), "\n") {
		if i == 0 {
			continue // interface line
		}
		f := strings.Split(line, "\t")
		if len(f) < 7 {
			continue
		}
		peers = append(peers, peerState{
			PublicKey:     f[0],
			Endpoint:      noneToEmpty(f[2]),
			LastHandshake: atoi64(f[4]),
			RxBytes:       atoi64(f[5]),
			TxBytes:       atoi64(f[6]),
			ViaRelay:      isRelayEndpoint(f[2]),
		})
	}
	return peers
}

// relayEndpoints is the set of source addresses the relay sends from.
//
// Set from RELAY_PEER_ADDRS at startup. Empty means the deployment has
// no relay, in which case nothing is ever reported as relayed — which
// is correct rather than merely safe.
var relayEndpoints []string

func isRelayEndpoint(endpoint string) bool {
	if endpoint == "" || endpoint == "(none)" {
		return false
	}
	host := endpoint
	if i := strings.LastIndex(endpoint, ":"); i > 0 {
		host = endpoint[:i]
	}
	for _, r := range relayEndpoints {
		if host == r {
			return true
		}
	}
	return false
}

// responderAnswers asks the responder itself.
//
// 1.7.31 checked for /run/responder-ready. The agent shares the
// gateway's *network* namespace (network_mode: service:), not its
// filesystem, so that file was never visible from here and the card
// read 응답 서버 없음 while phones were reaching :8080 in 244 ms. A
// shared network namespace means 10.78.0.1 is local: connect to it.
func responderAnswers() bool {
	c := &http.Client{Timeout: 2 * time.Second}
	resp, err := c.Get("http://10.78.0.1:8080/")
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	return resp.StatusCode == http.StatusOK
}

func noneToEmpty(v string) string {
	if v == "(none)" {
		return ""
	}
	return v
}

func atoi64(s string) int64 {
	n, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	if err != nil {
		return 0
	}
	return n
}

// detectBackend distinguishes the kernel module from wireguard-go.
//
// /sys/module/wireguard exists when the module is loaded. wg-quick uses
// the module when it can and falls back otherwise, so the presence of
// that directory is what actually decides which path carried the
// interface — not anything the agent chose.
func detectBackend() string {
	if _, err := os.Stat("/sys/module/wireguard"); err == nil {
		return "kernel"
	}
	return "userspace"
}

// interfaceState reports whether the device exists and how many peers
// it holds.
//
// `wg show <dev> peers` prints one key per line and exits non-zero when
// the device is absent, which is exactly the distinction needed.
func interfaceState(device string) (up bool, peers int) {
	out, err := exec.Command("wg", "show", device, "peers").Output()
	if err != nil {
		return false, 0
	}
	lines := strings.Fields(strings.TrimSpace(string(out)))
	return true, len(lines)
}

func postReport(
	ctx context.Context,
	client *http.Client,
	controllerURL, token, device, version string,
) error {
	up, peers := interfaceState(device)
	body, err := json.Marshal(nodeReport{
		WGBackend:     detectBackend(),
		WGInterfaceUp: up,
		PeerCount:     peers,
		AgentVersion:  version,
		Peers:         peerStates(device),
		ResponderUp:   responderAnswers(),
	})
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		strings.TrimRight(controllerURL, "/")+"/node/report", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("node report: HTTP %d", resp.StatusCode)
	}
	return nil
}

// reportLoop runs alongside the peer sync.
//
// Separate from it on purpose: a failing report must not stop peers
// being applied. A gateway that cannot reach the controller to say
// hello should still enforce the last policy it was given.
func reportLoop(
	ctx context.Context,
	client *http.Client,
	controllerURL, token, device, version string,
	every time.Duration,
) {
	tick := time.NewTicker(every)
	defer tick.Stop()
	for {
		// Clear idle endpoints on the same cycle.
		//
		// Same 180-second criterion the report uses to decide a peer is
		// live, so the two never disagree about which peers are idle.
		if n, err := forgetIdleEndpoints(device); err != nil {
			fmt.Fprintf(os.Stderr, "forget idle endpoints: %v\n", err)
		} else if n > 0 {
			fmt.Printf("cleared %d idle peer endpoint(s)\n", n)
		}

		if err := postReport(ctx, client, controllerURL, token, device, version); err != nil {
			// Logged, not fatal — see above.
			fmt.Fprintf(os.Stderr, "node report failed: %v\n", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}
