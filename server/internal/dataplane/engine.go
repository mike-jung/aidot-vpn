// Package dataplane is the data-node-side counterpart to internal/nodes.
//
// Engine is the interface the agent uses to apply peer configurations to
// the local WireGuard device and to read per-peer telemetry back. The
// production implementation wraps wgctrl-go (or its AmneziaWG fork at
// github.com/Jipok/wgctrl-go); the in-memory implementation in this file
// is exhaustively tested in this sandbox and is also used by integration
// tests that don't need a real kernel WG interface.
//
// The agent loop in sync.go composes Engine with a ControllerClient (the
// controller-side gRPC peer) into a self-contained reconciler.
package dataplane

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"time"
)

// PeerConfig is the desired state for one peer. It mirrors PeerSpec on
// the controller side but with the [32]byte key types the kernel speaks.
type PeerConfig struct {
	PublicKey                  [32]byte
	PSK                        [32]byte
	AllowedIPs                 []netip.Prefix
	PersistentKeepaliveSeconds uint32
}

// DeviceConfig is the desired state for the local WG interface.
type DeviceConfig struct {
	PrivateKey [32]byte
	ListenPort int
	Peers      []PeerConfig
	// ReplacePeers, when true, instructs the engine to remove any peer
	// not present in Peers. The agent passes this on every full Sync.
	ReplacePeers bool
}

// PeerState is one row of telemetry the engine reads back from the kernel.
type PeerState struct {
	PublicKey     [32]byte
	LastHandshake time.Time
	RxBytes       int64
	TxBytes       int64
	Endpoint      netip.AddrPort
}

// DeviceState is the current observed state of the WG interface.
type DeviceState struct {
	PublicKey [32]byte
	Peers     []PeerState
}

// Engine abstracts the kernel WireGuard device control plane.
type Engine interface {
	// Configure applies cfg to the device named `dev`. If `dev` does not
	// exist yet, the engine is responsible for creating it (production
	// implementation uses `ip link add dev <name> type wireguard`).
	Configure(ctx context.Context, dev string, cfg DeviceConfig) error

	// Read returns the current state of the named device.
	Read(ctx context.Context, dev string) (*DeviceState, error)

	// Close releases resources. Idempotent.
	Close() error
}

// ErrNoDevice is returned when an interface name does not exist.
var ErrNoDevice = errors.New("dataplane: device not found")

// MemoryEngine is an in-memory Engine implementation suitable for tests.
//
// It models a real WG kernel device closely enough for sync-loop logic:
//
//   - Configure() respects ReplacePeers semantics (full replacement)
//   - Configure() merges peers when ReplacePeers is false
//   - Each peer's RxBytes/TxBytes/LastHandshake are accumulated through
//     the InjectTelemetry helper so tests can simulate handshakes and
//     traffic without an actual kernel.
type MemoryEngine struct {
	mu      sync.Mutex
	devices map[string]*memoryDev
}

type memoryDev struct {
	publicKey  [32]byte
	listenPort int
	peers      map[[32]byte]*memoryPeer
}

type memoryPeer struct {
	psk                 [32]byte
	allowedIPs          []netip.Prefix
	persistentKeepalive uint32
	rxBytes             int64
	txBytes             int64
	lastHandshake       time.Time
	endpoint            netip.AddrPort
}

// NewMemoryEngine returns a fresh Engine that operates entirely in memory.
func NewMemoryEngine() *MemoryEngine {
	return &MemoryEngine{devices: make(map[string]*memoryDev)}
}

// Configure implements Engine.
func (e *MemoryEngine) Configure(ctx context.Context, dev string, cfg DeviceConfig) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	e.mu.Lock()
	defer e.mu.Unlock()

	d, ok := e.devices[dev]
	if !ok {
		d = &memoryDev{peers: make(map[[32]byte]*memoryPeer)}
		e.devices[dev] = d
	}
	d.publicKey = cfg.PrivateKey // simulated: pretend pubkey == privkey for tests
	d.listenPort = cfg.ListenPort

	if cfg.ReplacePeers {
		// Build a new map; preserve telemetry only for peers still present.
		newPeers := make(map[[32]byte]*memoryPeer, len(cfg.Peers))
		for _, p := range cfg.Peers {
			existing := d.peers[p.PublicKey]
			peer := &memoryPeer{
				psk:                 p.PSK,
				allowedIPs:          append([]netip.Prefix(nil), p.AllowedIPs...),
				persistentKeepalive: p.PersistentKeepaliveSeconds,
			}
			if existing != nil {
				peer.rxBytes = existing.rxBytes
				peer.txBytes = existing.txBytes
				peer.lastHandshake = existing.lastHandshake
				peer.endpoint = existing.endpoint
			}
			newPeers[p.PublicKey] = peer
		}
		d.peers = newPeers
	} else {
		for _, p := range cfg.Peers {
			peer, ok := d.peers[p.PublicKey]
			if !ok {
				peer = &memoryPeer{}
				d.peers[p.PublicKey] = peer
			}
			peer.psk = p.PSK
			peer.allowedIPs = append([]netip.Prefix(nil), p.AllowedIPs...)
			peer.persistentKeepalive = p.PersistentKeepaliveSeconds
		}
	}
	return nil
}

// Read implements Engine.
func (e *MemoryEngine) Read(ctx context.Context, dev string) (*DeviceState, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	e.mu.Lock()
	defer e.mu.Unlock()

	d, ok := e.devices[dev]
	if !ok {
		return nil, ErrNoDevice
	}
	state := &DeviceState{
		PublicKey: d.publicKey,
		Peers:     make([]PeerState, 0, len(d.peers)),
	}
	for pk, p := range d.peers {
		state.Peers = append(state.Peers, PeerState{
			PublicKey:     pk,
			LastHandshake: p.lastHandshake,
			RxBytes:       p.rxBytes,
			TxBytes:       p.txBytes,
			Endpoint:      p.endpoint,
		})
	}
	return state, nil
}

// Close implements Engine.
func (e *MemoryEngine) Close() error { return nil }

// InjectTelemetry simulates kernel-observed traffic on a peer. Tests use
// this to advance the engine's view of session state without involving a
// real WG interface.
func (e *MemoryEngine) InjectTelemetry(dev string, pubkey [32]byte, rx, tx int64, handshake time.Time, ep netip.AddrPort) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	d, ok := e.devices[dev]
	if !ok {
		return ErrNoDevice
	}
	p, ok := d.peers[pubkey]
	if !ok {
		return errors.New("InjectTelemetry: peer not found")
	}
	p.rxBytes = rx
	p.txBytes = tx
	p.lastHandshake = handshake
	p.endpoint = ep
	return nil
}

// PeerCount returns the number of peers currently configured on the
// named device. Helpful for tests that assert on convergence.
func (e *MemoryEngine) PeerCount(dev string) int {
	e.mu.Lock()
	defer e.mu.Unlock()
	d, ok := e.devices[dev]
	if !ok {
		return 0
	}
	return len(d.peers)
}
