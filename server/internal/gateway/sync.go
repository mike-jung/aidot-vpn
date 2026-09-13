package gateway

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"time"
)

// Syncer pulls desired state from the controller and applies it locally.
//
// Two things are applied, and the split matters:
//
//   - WireGuard peers, via `wg set`. This decides who can complete a
//     handshake at all.
//   - nftables rules, via `nft -f`. This decides what a peer that HAS
//     completed a handshake is allowed to reach.
//
// Keeping them separate is deliberate. A device that loses its policy
// keeps its WG peer (so it handshakes and its traffic is visibly dropped,
// which an admin can diagnose) rather than silently failing to connect,
// which looks identical to a broken key or a network outage.
type Syncer struct {
	ControllerURL string
	NodeToken     string
	WGInterface   string
	LogDenied     bool
	Interval      time.Duration
	HTTP          *http.Client
	Logger        *slog.Logger

	// Runner executes local commands. Swapped in tests.
	Runner CommandRunner

	syncMu        sync.Mutex // Serialize complete poll/apply cycles.
	mu            sync.Mutex
	lastRulesHash string
	lastPeerSet   map[string]string // pubkey -> allowed-ips
	stats         Stats
}

// Stats is exposed on the agent's /metrics endpoint.
type Stats struct {
	Polls        uint64
	PollErrors   uint64
	RuleApplies  uint64
	PeerApplies  uint64
	ApplyErrors  uint64
	LastSyncUnix int64
	PeerCount    int
}

// CommandRunner abstracts `wg` and `nft` invocation.
type CommandRunner interface {
	Run(ctx context.Context, name string, args []string, stdin string) (string, error)
}

// ExecRunner is the production CommandRunner.
type ExecRunner struct{}

func (ExecRunner) Run(ctx context.Context, name string, args []string, stdin string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	out, err := cmd.CombinedOutput()
	return string(out), err
}

type peersResponse struct {
	NodeID      string     `json:"node_id"`
	Hostname    string     `json:"hostname"`
	GeneratedAt string     `json:"generated_at"`
	Peers       []peerWire `json:"peers"`
}

type peerWire struct {
	DeviceID    string     `json:"device_id"`
	PublicKey   string     `json:"public_key"`
	PSK         string     `json:"psk"`
	IPv4        string     `json:"ipv4"`
	IPv6        string     `json:"ipv6"`
	Status      string     `json:"status"`
	PolicyBound bool       `json:"policy_bound"`
	DestCIDRs   []string   `json:"dest_cidrs"`
	Rules       []ruleWire `json:"rules"`
	Rewrites    []struct {
		Virtual string `json:"virtual"`
		Real    string `json:"real"`
	} `json:"rewrites"`
	NATCIDRs []string `json:"nat_cidrs"`
}

type ruleWire struct {
	Action   string `json:"action"`
	Dst      string `json:"dst"`
	Protocol string `json:"protocol"`
	PortMin  uint16 `json:"port_min"`
	PortMax  uint16 `json:"port_max"`
}

// Stats returns a snapshot of the agent's counters.
func (s *Syncer) Stats() Stats {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.stats
}

func (s *Syncer) Ready(now time.Time, maxAge time.Duration) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stats.LastSyncUnix == 0 || maxAge <= 0 {
		return false
	}
	age := now.Sub(time.Unix(s.stats.LastSyncUnix, 0))
	return age >= 0 && age <= maxAge
}

// ensureDefaults fills in the optional fields.
//
// Called from both Run and SyncOnce because SyncOnce is part of the
// public surface — an operator-triggered one-shot resync must not depend
// on Run having been called first.
func (s *Syncer) ensureDefaults() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.Interval <= 0 {
		s.Interval = 15 * time.Second
	}
	if s.HTTP == nil {
		s.HTTP = &http.Client{Timeout: 20 * time.Second}
	}
	if s.Logger == nil {
		s.Logger = slog.Default()
	}
	if s.Runner == nil {
		s.Runner = ExecRunner{}
	}
	if s.WGInterface == "" {
		s.WGInterface = "wg0"
	}
}

// Run loops until ctx is cancelled.
func (s *Syncer) Run(ctx context.Context) error {
	s.ensureDefaults()

	ticker := time.NewTicker(s.Interval)
	defer ticker.Stop()

	// Apply immediately rather than waiting a full interval — a gateway
	// restarting after a crash should re-establish enforcement now, not
	// in 15 seconds.
	if err := s.SyncOnce(ctx); err != nil {
		s.Logger.Warn("initial sync failed", "err", err.Error())
	}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if err := s.SyncOnce(ctx); err != nil {
				s.Logger.Warn("sync failed", "err", err.Error())
			}
		}
	}
}

// SyncOnce performs one poll-and-apply cycle.
func (s *Syncer) SyncOnce(ctx context.Context) error {
	s.syncMu.Lock()
	defer s.syncMu.Unlock()
	s.ensureDefaults()

	resp, err := s.fetchPeers(ctx)
	if err != nil {
		s.mu.Lock()
		s.stats.Polls++
		s.stats.PollErrors++
		s.mu.Unlock()
		return err
	}
	s.mu.Lock()
	s.stats.Polls++
	s.stats.PeerCount = len(resp.Peers)
	s.mu.Unlock()

	peers := make([]Peer, 0, len(resp.Peers))
	for _, p := range resp.Peers {
		var rewrites []Rewrite
		for _, rw := range p.Rewrites {
			rewrites = append(rewrites, Rewrite{Virtual: rw.Virtual, Real: rw.Real})
		}
		rules := make([]Rule, 0, len(p.Rules))
		for _, r := range p.Rules {
			rules = append(rules, Rule{
				Action: r.Action, Dst: r.Dst, Protocol: r.Protocol,
				PortMin: r.PortMin, PortMax: r.PortMax,
			})
		}
		peers = append(peers, Peer{
			DeviceID: p.DeviceID, PublicKey: p.PublicKey,
			IPv4: p.IPv4, IPv6: p.IPv6, Status: p.Status,
			PolicyBound: p.PolicyBound, DestCIDRs: p.DestCIDRs, Rules: rules,
			PSK:      p.PSK,
			NATCIDRs: p.NATCIDRs, Rewrites: rewrites,
		})
	}

	// Firewall first, then peers.
	//
	// Ordering is a security decision, not a style one. If we added a new
	// peer before its rules existed, there would be a window — up to the
	// length of an nft apply — where that peer could handshake and
	// forward traffic against whatever the previous ruleset said. Applying
	// rules first means a new peer's first packet always meets its own
	// policy.
	if err := s.applyRules(ctx, peers); err != nil {
		s.mu.Lock()
		s.stats.ApplyErrors++
		s.mu.Unlock()
		return fmt.Errorf("apply nftables: %w", err)
	}
	if err := s.applyPeers(ctx, peers); err != nil {
		s.mu.Lock()
		s.stats.ApplyErrors++
		s.mu.Unlock()
		return fmt.Errorf("apply wg peers: %w", err)
	}

	s.mu.Lock()
	s.stats.LastSyncUnix = time.Now().Unix()
	s.mu.Unlock()
	return nil
}

func (s *Syncer) fetchPeers(ctx context.Context) (*peersResponse, error) {
	url := strings.TrimRight(s.ControllerURL, "/") + "/node/peers"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+s.NodeToken)
	req.Header.Set("Accept", "application/json")

	res, err := s.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("controller returned %s", res.Status)
	}
	var out peersResponse
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("decode peers: %w", err)
	}
	return &out, nil
}

// applyRules renders and installs the nftables ruleset, skipping the
// kernel round-trip when nothing changed.
func (s *Syncer) applyRules(ctx context.Context, peers []Peer) error {
	script := Render(peers, RenderOptions{
		WGInterface: s.WGInterface,
		LogDenied:   s.LogDenied,
	})
	sum := sha256.Sum256([]byte(script))
	hash := hex.EncodeToString(sum[:])

	s.mu.Lock()
	unchanged := hash == s.lastRulesHash
	s.mu.Unlock()
	if unchanged {
		return nil
	}

	if out, err := s.Runner.Run(ctx, "nft", []string{"-f", "-"}, script); err != nil {
		// Deliberately do NOT update lastRulesHash here. A failed apply
		// must be retried on the next tick, and caching the hash of a
		// ruleset that never loaded would make the agent believe it had
		// enforced a policy it hadn't.
		return fmt.Errorf("nft -f: %w (%s)", err, strings.TrimSpace(out))
	}

	s.mu.Lock()
	s.lastRulesHash = hash
	s.stats.RuleApplies++
	s.mu.Unlock()
	s.Logger.Info("nftables ruleset applied",
		"peers", len(peers), "hash", hash[:12])
	return nil
}

// applyPeers reconciles the WG peer set: add/update the peers the
// controller lists, remove any the kernel has but the controller doesn't.
func (s *Syncer) applyPeers(ctx context.Context, peers []Peer) error {
	want := map[string]string{}
	// PSK per public key, alongside allowed-ips. `wg set` takes the key
	// from a file rather than an argument so it never appears in a
	// process listing; written 0600 under a private temp dir and removed
	// after each call.
	psks := map[string]string{}
	for _, p := range peers {
		if p.PSK != "" {
			psks[p.PublicKey] = p.PSK
		}
		if p.PublicKey == "" {
			continue
		}
		var allowed []string
		if p.IPv4 != "" {
			allowed = append(allowed, p.IPv4+"/32")
		}
		if p.IPv6 != "" {
			allowed = append(allowed, p.IPv6+"/128")
		}
		if len(allowed) == 0 {
			continue
		}
		sort.Strings(allowed)
		// Server-side AllowedIPs is cryptokey routing: it says which
		// SOURCE addresses this peer may use. It is NOT a destination
		// ACL — that is what the nftables table above is for. Setting it
		// to the peer's own tunnel address prevents a peer from spoofing
		// another device's source IP.
		// PSK folded into the compared value, so a rotated key is
		// re-applied rather than skipped as "unchanged".
		want[p.PublicKey] = strings.Join(allowed, ",") + "|" + p.PSK
	}

	s.mu.Lock()
	same := len(want) == len(s.lastPeerSet)
	if same {
		for k, v := range want {
			if s.lastPeerSet[k] != v {
				same = false
				break
			}
		}
	}
	s.mu.Unlock()

	have, err := s.currentPeers(ctx)
	if err != nil {
		return err
	}
	if same && mapsEqual(have, want) {
		return nil
	}

	var applied int
	for pub, wantVal := range want {
		allowed := strings.SplitN(wantVal, "|", 2)[0]
		if have[pub] == wantVal {
			continue
		}
		args := []string{"set", s.WGInterface, "peer", pub, "allowed-ips", allowed}
		var pskFile string
		if psk, ok := psks[pub]; ok {
			f, err := os.CreateTemp("", "wgpsk-*")
			if err != nil {
				return fmt.Errorf("psk tempfile: %w", err)
			}
			pskFile = f.Name()
			if _, err := f.WriteString(psk + "\n"); err != nil {
				f.Close()
				os.Remove(pskFile)
				return fmt.Errorf("psk write: %w", err)
			}
			f.Close()
			_ = os.Chmod(pskFile, 0o600)
			args = append(args, "preshared-key", pskFile)
		} else {
			// Omitting the option retains the old key. An empty file clears it (wg(8)).
			args = append(args, "preshared-key", os.DevNull)
		}
		out, err := s.Runner.Run(ctx, "wg", args, "")
		if pskFile != "" {
			os.Remove(pskFile)
		}
		if err != nil {
			return fmt.Errorf("wg set peer %s: %w (%s)", short(pub), err, strings.TrimSpace(out))
		}
		applied++
	}
	for pub := range have {
		if _, keep := want[pub]; keep {
			continue
		}
		if out, err := s.Runner.Run(ctx, "wg",
			[]string{"set", s.WGInterface, "peer", pub, "remove"}, ""); err != nil {
			s.Logger.Warn("wg peer remove failed",
				"peer", short(pub), "err", err.Error(), "out", strings.TrimSpace(out))
			return fmt.Errorf("remove wg peer %s: %w", short(pub), err)
		}
		applied++
	}

	s.mu.Lock()
	s.lastPeerSet = want
	if applied > 0 {
		s.stats.PeerApplies++
	}
	s.mu.Unlock()
	if applied > 0 {
		s.Logger.Info("wg peers reconciled", "changes", applied, "desired", len(want))
	}
	return nil
}

// currentPeers reads the kernel's view via `wg show <dev> dump`.
//
// Dump format is tab-separated; peer lines are:
//
//	pubkey  psk  endpoint  allowed-ips  handshake  rx  tx  keepalive
//
// The first line is the interface itself and is skipped.
func (s *Syncer) currentPeers(ctx context.Context) (map[string]string, error) {
	out, err := s.Runner.Run(ctx, "wg", []string{"show", s.WGInterface, "dump"}, "")
	if err != nil {
		return nil, fmt.Errorf("wg show dump: %w (%s)", err, strings.TrimSpace(out))
	}
	res := map[string]string{}
	for i, line := range strings.Split(strings.TrimSpace(out), "\n") {
		if i == 0 || strings.TrimSpace(line) == "" {
			continue
		}
		f := strings.Split(line, "\t")
		if len(f) < 4 {
			continue
		}
		allowed := f[3]
		if allowed == "(none)" {
			allowed = ""
		}
		parts := strings.Split(allowed, ",")
		sort.Strings(parts)
		// Column 1 of `wg show dump` is the pre-shared key — "(none)" or
		// base64. Folded into the value the same way applyPeers folds it
		// into `want`, so the two compare like for like.
		psk := f[1]
		if psk == "(none)" {
			psk = ""
		}
		res[f[0]] = strings.Join(parts, ",") + "|" + psk
	}
	return res, nil
}

func mapsEqual(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}
