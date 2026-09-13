// IP allocator for AidotVpn devices.
//
// Each tenant has a CIDR pool (e.g. 10.78.0.0/16). Addresses are assigned
// to *active* device keys. We pick the lowest unused address in the pool
// above .1 (we reserve .0 = network, .1 = gateway).
//
// The current implementation walks the pool linearly. For pools <= /16
// (~65k addresses), the cost is bounded and acceptable. Larger pools, or
// multi-tenant deployments with high churn, will want a packed bitmap or
// a separate ip_pool_allocations table indexed by integer IP.
package devices

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/netip"

	"github.com/aidotvpn/server/internal/domain"
)

// ErrPoolExhausted is returned when no addresses are available in the
// requested pool. Operators should expand the tenant's pool when they
// see this in production.
var ErrPoolExhausted = errors.New("devices: IP pool exhausted")

// allocateIPv4 returns the lowest unused IPv4 address inside `pool`,
// excluding .0 (network) and .1 (gateway). Used addresses are read
// from device_keys.ipv4_addr where revoked_at IS NULL.
//
// q is either *sql.DB or *sql.Tx — both implement QueryContext.
func allocateIPv4(ctx context.Context, q querier, tenantID domain.ID, pool netip.Prefix) (netip.Addr, error) {
	if !pool.Addr().Is4() {
		return netip.Addr{}, fmt.Errorf("allocateIPv4: pool %s is not IPv4", pool)
	}

	// Pull the set of in-use addresses for this tenant.
	rows, err := q.QueryContext(ctx, `
		SELECT dk.ipv4_addr
		FROM device_keys dk
		JOIN devices d ON d.id = dk.device_id
		WHERE d.tenant_id = ?
		  AND dk.revoked_at IS NULL
		  AND dk.ipv4_addr IS NOT NULL`,
		tenantID.Bytes())
	if err != nil {
		return netip.Addr{}, fmt.Errorf("allocateIPv4 query: %w", err)
	}
	defer rows.Close()

	used := make(map[[4]byte]struct{})
	for rows.Next() {
		var b []byte
		if err := rows.Scan(&b); err != nil {
			return netip.Addr{}, fmt.Errorf("allocateIPv4 scan: %w", err)
		}
		if len(b) == 4 {
			used[[4]byte{b[0], b[1], b[2], b[3]}] = struct{}{}
		}
	}
	if err := rows.Err(); err != nil {
		return netip.Addr{}, err
	}

	// Walk from pool.Addr() + 2 (skip .0 and .1) until we find a hole or
	// reach the broadcast / pool end.
	start := pool.Addr().As4()
	startU := uint32(start[0])<<24 | uint32(start[1])<<16 | uint32(start[2])<<8 | uint32(start[3])
	bits := uint(pool.Bits())
	if bits > 30 {
		// /31 and /32 don't have meaningful host space for our use.
		return netip.Addr{}, fmt.Errorf("allocateIPv4: pool %s too narrow", pool)
	}
	hostCount := uint32(1) << (32 - bits)
	// Reserve last as broadcast for /24 and wider.
	for i := uint32(2); i < hostCount-1; i++ {
		ip := startU + i
		candidate := [4]byte{
			byte(ip >> 24), byte(ip >> 16), byte(ip >> 8), byte(ip),
		}
		if _, taken := used[candidate]; taken {
			continue
		}
		return netip.AddrFrom4(candidate), nil
	}
	return netip.Addr{}, ErrPoolExhausted
}

// allocateIPv6 returns the lowest unused IPv6 in `pool`, skipping the
// pool's network address (::0) and the first gateway address (::1).
// Same linear-walk caveat applies.
func allocateIPv6(ctx context.Context, q querier, tenantID domain.ID, pool netip.Prefix) (netip.Addr, error) {
	if !pool.Addr().Is6() {
		return netip.Addr{}, fmt.Errorf("allocateIPv6: pool %s is not IPv6", pool)
	}

	rows, err := q.QueryContext(ctx, `
		SELECT dk.ipv6_addr
		FROM device_keys dk
		JOIN devices d ON d.id = dk.device_id
		WHERE d.tenant_id = ?
		  AND dk.revoked_at IS NULL
		  AND dk.ipv6_addr IS NOT NULL`,
		tenantID.Bytes())
	if err != nil {
		return netip.Addr{}, fmt.Errorf("allocateIPv6 query: %w", err)
	}
	defer rows.Close()

	used := make(map[[16]byte]struct{})
	for rows.Next() {
		var b []byte
		if err := rows.Scan(&b); err != nil {
			return netip.Addr{}, fmt.Errorf("allocateIPv6 scan: %w", err)
		}
		if len(b) == 16 {
			var k [16]byte
			copy(k[:], b)
			used[k] = struct{}{}
		}
	}
	if err := rows.Err(); err != nil {
		return netip.Addr{}, err
	}

	// For IPv6 we walk by incrementing the bottom 64 bits only — that
	// gives us 2^64 candidates which is plenty even for the largest
	// realistic pool. We skip ::0 and ::1.
	base := pool.Addr().As16()
	for i := uint64(2); i < uint64(1<<60); i++ {
		// Increment last 8 bytes by i.
		candidate := base
		carry := i
		for j := 15; j >= 8 && carry > 0; j-- {
			sum := uint64(candidate[j]) + (carry & 0xFF)
			candidate[j] = byte(sum & 0xFF)
			carry = (carry >> 8) + (sum >> 8)
		}
		// Bound check: candidate must still be within the prefix.
		if !pool.Contains(netip.AddrFrom16(candidate)) {
			return netip.Addr{}, ErrPoolExhausted
		}
		if _, taken := used[candidate]; taken {
			continue
		}
		return netip.AddrFrom16(candidate).Unmap(), nil
	}
	return netip.Addr{}, ErrPoolExhausted
}

// querier is the subset of *sql.DB / *sql.Tx we need for read queries.
type querier interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}
