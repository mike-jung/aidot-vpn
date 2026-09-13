// Package nodes implements the controller side of NodeService: building
// the authoritative peer list a data-node should be serving, recording
// session telemetry the node reports back, and producing a stable
// version token so polling can be efficient.
//
// Like internal/devices, this package is transport-agnostic. The
// Connect-go handlers in cmd/controller wrap thin adapters around the
// methods here.
package nodes

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"time"

	"github.com/aidotvpn/server/internal/audit"
	"github.com/aidotvpn/server/internal/domain"
)

// ErrNotFound is returned for missing rows.
var ErrNotFound = errors.New("nodes: not found")

// Node represents a row in the nodes table.
type Node struct {
	ID         domain.ID
	TenantID   domain.ID
	Hostname   string
	Region     string
	Status     string
	LastSeenAt *time.Time

	// What the gateway reports about itself.
	//
	// Status is an admin decision and says nothing about whether the
	// process is alive; these say whether it is, and how the tunnel is
	// actually being carried. A seed row reads 활성 with all of these
	// empty, which is precisely the state that used to look healthy
	// while nothing worked.
	LastReportAt  *time.Time
	WGBackend     string // "kernel" | "userspace" | ""
	WGInterfaceUp *bool
	PeerCount     *int
	AgentVersion  string
	ResponderUp   *bool
}

// PeerSpec mirrors the proto message but with Go-native types.
type PeerSpec struct {
	PublicKey                  []byte // 32 bytes
	PSK                        []byte // 32 bytes
	AllowedIPs                 []netip.Prefix
	PersistentKeepaliveSeconds uint32
}

// SyncResult is the output of Service.Sync.
type SyncResult struct {
	Version     string // opaque "<seq>-<hex>"
	Peers       []PeerSpec
	NotModified bool
}

// SessionStat is the input shape for Service.ReportSessions.
type SessionStat struct {
	PeerPublicKey []byte
	LastHandshake time.Time
	RxBytes       int64
	TxBytes       int64
	EndpointMode  string
	ClientIP      netip.Addr // optional; data plane sees post-NAT IP
}

// Service composes peer-list construction and session recording.
type Service struct {
	db                *sql.DB
	audit             *audit.Writer
	defaultKeepalive  uint32
	defaultPolicyMode string
	now               func() time.Time
}

// Config configures a Service.
type Config struct {
	DB                  *sql.DB
	Audit               *audit.Writer
	DefaultKeepaliveSec uint32 // default 25 seconds
	Now                 func() time.Time
}

// New returns a Service ready to handle node operations.
func New(cfg Config) (*Service, error) {
	if cfg.DB == nil {
		return nil, errors.New("nodes.New: DB is required")
	}
	if cfg.Audit == nil {
		return nil, errors.New("nodes.New: Audit is required")
	}
	s := &Service{
		db:               cfg.DB,
		audit:            cfg.Audit,
		defaultKeepalive: cfg.DefaultKeepaliveSec,
		now:              cfg.Now,
	}
	if s.defaultKeepalive == 0 {
		s.defaultKeepalive = 25
	}
	if s.now == nil {
		s.now = func() time.Time { return time.Now().UTC() }
	}
	return s, nil
}

// FindByID looks up a node by primary key.
// RecordReport stores what the gateway agent says about itself.
//
// Deliberately does not touch status: a node an operator disabled must
// not bring itself back by reporting in.
func (s *Service) RecordReport(
	ctx context.Context,
	id domain.ID,
	backend string,
	interfaceUp bool,
	peerCount int,
	agentVersion string,
	responderUp bool,
) error {
	res, err := s.db.ExecContext(ctx, `
		UPDATE nodes
		   SET last_report_at = CURRENT_TIMESTAMP(6),
		       wg_backend = ?, wg_interface_up = ?,
		       peer_count = ?, agent_version = ?, responder_up = ?
		 WHERE id = ?`,
		backend, interfaceUp, peerCount, agentVersion, responderUp, id.Bytes())
	if err != nil {
		return fmt.Errorf("nodes.RecordReport: %w", err)
	}
	// Existence by RowsAffected is wrong here for the same reason it was
	// wrong in policies.Update: an agent reporting identical values
	// changes nothing, and a node that exists must not read as missing.
	_ = res
	return nil
}

func (s *Service) FindByID(ctx context.Context, id domain.ID) (*Node, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, tenant_id, hostname, region, status, last_seen_at,
		       last_report_at, wg_backend, wg_interface_up, peer_count,
		       agent_version, responder_up
		FROM nodes
		WHERE id = ? AND deleted_at IS NULL
		LIMIT 1`,
		id.Bytes())
	return scanNodeWithRuntime(row)
}

// FindByHostname is used during RegisterNode to confirm the node's
// self-reported hostname matches what was provisioned.
func (s *Service) FindByHostname(ctx context.Context, tenantID domain.ID, hostname string) (*Node, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, tenant_id, hostname, region, status, last_seen_at,
		       last_report_at, wg_backend, wg_interface_up, peer_count,
		       agent_version, responder_up
		FROM nodes
		WHERE tenant_id = ? AND hostname = ? AND deleted_at IS NULL
		LIMIT 1`,
		tenantID.Bytes(), hostname)
	return scanNodeWithRuntime(row)
}

// ListByTenant returns every non-deleted node visible to a tenant. The
// admin console uses this to populate the Nodes screen.
//
// We sort by hostname for stable display. The query is unbounded; in
// production with thousands of nodes you'd add pagination, but for now
// fleets stay small (<100 nodes per tenant) so this is fine.
func (s *Service) ListByTenant(ctx context.Context, tenantID domain.ID) ([]Node, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, tenant_id, hostname, region, status, last_seen_at,
		       last_report_at, wg_backend, wg_interface_up, peer_count,
		       agent_version, responder_up
		FROM nodes
		WHERE tenant_id = ? AND deleted_at IS NULL
		ORDER BY hostname ASC`,
		tenantID.Bytes())
	if err != nil {
		return nil, fmt.Errorf("nodes.ListByTenant: %w", err)
	}
	defer rows.Close()

	var out []Node
	for rows.Next() {
		n, err := scanNodeWithRuntime(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *n)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("nodes.ListByTenant rows: %w", err)
	}
	return out, nil
}

// MarkSeen updates last_seen_at on the node row. Called every time a
// node calls into NodeService.
func (s *Service) MarkSeen(ctx context.Context, id domain.ID) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE nodes SET last_seen_at = NOW(6) WHERE id = ? AND deleted_at IS NULL`,
		id.Bytes())
	return err
}

// Sync builds the authoritative peer list this node should serve and
// returns it together with a version token. If `currentVersion` matches
// the freshly-computed version, NotModified is true and Peers is empty.
//
// The peer list is the set of all *active* device_keys for the node's
// tenant whose owning device is in status active or suspended. Suspended
// devices remain enumerated so the data plane keeps existing tunnels
// (until rotation) but the controller can still cleanly revoke later.
func (s *Service) Sync(ctx context.Context, nodeID domain.ID, currentVersion string) (*SyncResult, error) {
	node, err := s.FindByID(ctx, nodeID)
	if err != nil {
		return nil, fmt.Errorf("Sync: lookup node: %w", err)
	}

	peers, seq, err := s.loadActivePeers(ctx, node.TenantID)
	if err != nil {
		return nil, err
	}
	version := computeVersion(seq, peers)
	_ = s.MarkSeen(ctx, nodeID)

	if currentVersion != "" && currentVersion == version {
		return &SyncResult{
			Version:     version,
			NotModified: true,
		}, nil
	}
	return &SyncResult{
		Version: version,
		Peers:   peers,
	}, nil
}

// ReportSessions persists session telemetry. Each row references a peer
// public key; we resolve to a device_key id and a node id, then upsert a
// `sessions` row keyed on (device_key_id, node_id).
//
// Unknown public keys (peers the data node still has but the controller
// has revoked) are counted as `rejected` so the agent can evict them.
func (s *Service) ReportSessions(ctx context.Context, nodeID domain.ID, stats []SessionStat) (accepted, rejected uint32, err error) {
	if len(stats) == 0 {
		return 0, 0, nil
	}

	// Resolve all public keys -> device_key_ids in one batch.
	keys := make([][]byte, 0, len(stats))
	for _, st := range stats {
		if len(st.PeerPublicKey) == 32 {
			keys = append(keys, st.PeerPublicKey)
		}
	}
	if len(keys) == 0 {
		return 0, uint32(len(stats)), nil
	}

	// Build placeholders dynamically; len <= ~1000 in practice.
	placeholders := make([]byte, 0, len(keys)*2)
	args := make([]any, 0, len(keys))
	for i, k := range keys {
		if i > 0 {
			placeholders = append(placeholders, ',')
		}
		placeholders = append(placeholders, '?')
		args = append(args, k)
	}
	q := "SELECT id, public_key FROM device_keys WHERE public_key IN (" + string(placeholders) +
		") AND revoked_at IS NULL"
	rows, qerr := s.db.QueryContext(ctx, q, args...)
	if qerr != nil {
		return 0, 0, fmt.Errorf("ReportSessions: lookup: %w", qerr)
	}
	keyIndex := make(map[string]domain.ID, len(keys))
	for rows.Next() {
		var id, pk []byte
		if err := rows.Scan(&id, &pk); err != nil {
			rows.Close()
			return 0, 0, err
		}
		var did domain.ID
		_ = did.Scan(id)
		keyIndex[string(pk)] = did
	}
	rows.Close()

	for _, st := range stats {
		dkID, ok := keyIndex[string(st.PeerPublicKey)]
		if !ok {
			rejected++
			continue
		}
		var clientIPArg any
		if st.ClientIP.IsValid() {
			clientIPArg = domain.IPToBytes(st.ClientIP)
		}
		// Try UPDATE first; if no row was open we INSERT a new session.
		// We deliberately don't add a unique constraint on (device_key_id,
		// ended_at IS NULL) because MariaDB lacks partial unique indexes.
		// The two-step approach preserves single-open-session semantics
		// without it.
		res, eerr := s.db.ExecContext(ctx, `
			UPDATE sessions
			SET last_handshake_at = ?, rx_bytes = ?, tx_bytes = ?, client_ip = ?
			WHERE device_key_id = ? AND ended_at IS NULL`,
			st.LastHandshake, st.RxBytes, st.TxBytes, clientIPArg,
			dkID.Bytes())
		if eerr != nil {
			rejected++
			continue
		}
		n, _ := res.RowsAffected()
		if n == 0 {
			_, eerr = s.db.ExecContext(ctx, `
				INSERT INTO sessions
				  (id, device_key_id, node_id, last_handshake_at,
				   rx_bytes, tx_bytes, client_ip)
				VALUES (?, ?, ?, ?, ?, ?, ?)`,
				domain.NewID().Bytes(), dkID.Bytes(), nodeID.Bytes(),
				st.LastHandshake, st.RxBytes, st.TxBytes, clientIPArg)
			if eerr != nil {
				rejected++
				continue
			}
		}
		accepted++
	}
	return accepted, rejected, nil
}

// --- internals ---------------------------------------------------------

// loadActivePeers returns the peer list for a tenant, joined with the
// PSK row, plus a monotonic "sequence" derived from the most recent
// device_key activation/revocation.
func (s *Service) loadActivePeers(ctx context.Context, tenantID domain.ID) ([]PeerSpec, int64, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT
		  dk.public_key,
		  dp.psk,
		  dk.ipv4_addr,
		  dk.ipv6_addr,
		  dk.activated_at
		FROM device_keys dk
		JOIN devices d ON d.id = dk.device_id AND d.tenant_id = ?
		LEFT JOIN device_psks dp
		  ON dp.device_key_id = dk.id AND dp.revoked_at IS NULL
		WHERE dk.revoked_at IS NULL
		  AND d.deleted_at IS NULL
		  AND d.status IN ('active', 'suspended')
		ORDER BY dk.activated_at ASC, dk.id ASC`,
		tenantID.Bytes())
	if err != nil {
		return nil, 0, fmt.Errorf("loadActivePeers: %w", err)
	}
	defer rows.Close()

	var peers []PeerSpec
	var maxSeq int64
	for rows.Next() {
		var (
			pk        []byte
			psk       []byte
			v4, v6    []byte
			activated time.Time
		)
		if err := rows.Scan(&pk, &psk, &v4, &v6, &activated); err != nil {
			return nil, 0, err
		}
		spec := PeerSpec{
			PublicKey:                  pk,
			PSK:                        psk,
			PersistentKeepaliveSeconds: s.defaultKeepalive,
		}
		if len(v4) == 4 {
			addr, _ := domain.IPFromBytes(v4)
			spec.AllowedIPs = append(spec.AllowedIPs, netip.PrefixFrom(addr, 32))
		}
		if len(v6) == 16 {
			addr, _ := domain.IPFromBytes(v6)
			spec.AllowedIPs = append(spec.AllowedIPs, netip.PrefixFrom(addr, 128))
		}
		peers = append(peers, spec)
		// We use unix-microseconds so revocations within the same second
		// still bump the sequence.
		if seq := activated.UnixMicro(); seq > maxSeq {
			maxSeq = seq
		}
	}
	return peers, maxSeq, rows.Err()
}

// computeVersion produces a deterministic version token over the peer set.
// Format: "<seq>-<hex>" where seq is the most recent activation timestamp
// and hex is the SHA-256 hash of the canonical encoding of the peers.
func computeVersion(seq int64, peers []PeerSpec) string {
	// Sort by public key for determinism (order should already be stable
	// from the SQL ORDER BY but defensive).
	sorted := make([]PeerSpec, len(peers))
	copy(sorted, peers)
	sort.Slice(sorted, func(i, j int) bool {
		return string(sorted[i].PublicKey) < string(sorted[j].PublicKey)
	})

	h := sha256.New()
	var buf [8]byte
	for _, p := range sorted {
		h.Write(p.PublicKey)
		h.Write(p.PSK)
		for _, ip := range p.AllowedIPs {
			ipb := domain.IPToBytes(ip.Addr())
			h.Write(ipb)
			h.Write([]byte{byte(ip.Bits())})
		}
		binary.BigEndian.PutUint32(buf[:4], p.PersistentKeepaliveSeconds)
		h.Write(buf[:4])
	}
	binary.BigEndian.PutUint64(buf[:], uint64(seq))
	h.Write(buf[:])
	return fmt.Sprintf("%d-%s", seq, hex.EncodeToString(h.Sum(nil)[:16]))
}

// --- scanners ----------------------------------------------------------

type rowScanner interface {
	Scan(dest ...any) error
}

// scanNodeWithRuntime reads the five reporting columns as well.
//
// Separate from scanNode because that one backs queries elsewhere that
// select the original six columns; widening it would break them. The
// list view is the only place the runtime fields are needed.
func scanNodeWithRuntime(s rowScanner) (*Node, error) {
	var (
		n                     Node
		idBytes, tenantBytes  []byte
		lastSeen, lastReport  sql.NullTime
		backend, agentVersion sql.NullString
		ifaceUp, responder    sql.NullBool
		peers                 sql.NullInt64
	)
	err := s.Scan(&idBytes, &tenantBytes, &n.Hostname, &n.Region, &n.Status,
		&lastSeen, &lastReport, &backend, &ifaceUp, &peers, &agentVersion, &responder)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("scanNodeWithRuntime: %w", err)
	}
	if err := n.ID.Scan(idBytes); err != nil {
		return nil, err
	}
	if err := n.TenantID.Scan(tenantBytes); err != nil {
		return nil, err
	}
	if lastSeen.Valid {
		t := lastSeen.Time
		n.LastSeenAt = &t
	}
	if lastReport.Valid {
		t := lastReport.Time
		n.LastReportAt = &t
	}
	n.WGBackend = backend.String
	n.AgentVersion = agentVersion.String
	if ifaceUp.Valid {
		b := ifaceUp.Bool
		n.WGInterfaceUp = &b
	}
	if peers.Valid {
		c := int(peers.Int64)
		n.PeerCount = &c
	}
	if responder.Valid {
		b := responder.Bool
		n.ResponderUp = &b
	}
	return &n, nil
}

func scanNode(s rowScanner) (*Node, error) {
	n := &Node{}
	var (
		idBytes, tenantBytes []byte
		lastSeen             sql.NullTime
	)
	err := s.Scan(&idBytes, &tenantBytes, &n.Hostname, &n.Region, &n.Status, &lastSeen)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("scanNode: %w", err)
	}
	if err := n.ID.Scan(idBytes); err != nil {
		return nil, err
	}
	if err := n.TenantID.Scan(tenantBytes); err != nil {
		return nil, err
	}
	if lastSeen.Valid {
		t := lastSeen.Time
		n.LastSeenAt = &t
	}
	return n, nil
}
