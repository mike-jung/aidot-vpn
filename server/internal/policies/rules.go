package policies

import (
	"context"
	"fmt"
	"net/netip"

	"github.com/aidotvpn/server/internal/domain"
)

// Rule is one L4 destination rule resolved for a device. It is the
// gateway-side counterpart to AllowedIP: where AllowedIP tells the
// *client* what to route, Rule tells the *gateway* what to permit.
//
// The distinction matters and is the whole point of 0.10.0. AllowedIPs
// live in the client's WireGuard config, which a rooted device can
// rewrite at will. Rules are compiled into the gateway's nftables
// ruleset, which the device cannot touch.
type Rule struct {
	// Action is one of "accept", "reject", "drop". Only "accept" rules
	// are emitted as nftables accepts; reject/drop are emitted ahead of
	// the accepts so an explicit denial wins over a broader allow.
	Action string
	// Dst is the destination prefix. Always valid.
	Dst netip.Prefix
	// Protocol is "any", "tcp", "udp", "icmp", or "icmpv6".
	Protocol string
	// PortMin/PortMax are 0 when the rule does not constrain ports, or
	// when Protocol has no port concept. Callers must check Protocol
	// before emitting a port match.
	PortMin uint16
	PortMax uint16
}

// HasPorts reports whether this rule constrains L4 ports. ICMP rules and
// protocol-any rules never do, even if the columns happen to be set.
func (r Rule) HasPorts() bool {
	if r.Protocol != "tcp" && r.Protocol != "udp" {
		return false
	}
	return r.PortMin != 0 || r.PortMax != 0
}

// GetEffectiveRules returns the L4 rules attached to the device's policy.
//
// Rule sources: a rule applies when it targets this device explicitly
// (source_device_id = the device), or when it targets no specific source
// at all (both source columns NULL = "any device on this policy"). Group
// rules are resolved through device_group_memberships.
//
// An empty result is NOT an error and NOT "allow everything" — the
// gateway treats a device with zero accept rules as reachable-nowhere.
// The CIDR list from GetEffectiveAllowedIPs is the coarse layer; these
// rules refine it. A device with CIDRs but no L4 rules gets its CIDRs
// permitted on all protocols and ports, which is the behaviour admins
// expect from the "허용 CIDR" console screen alone.
func (s *Service) GetEffectiveRules(ctx context.Context, deviceID domain.ID) ([]Rule, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT r.action, r.dst_addr, r.dst_bits, r.protocol,
		       COALESCE(r.dst_port_min, 0), COALESCE(r.dst_port_max, 0)
		  FROM devices d
		  LEFT JOIN device_groups g ON g.id = d.group_id AND g.tenant_id = d.tenant_id AND g.deleted_at IS NULL
		  JOIN policies p
		    ON p.id = COALESCE(d.policy_id, g.policy_id) AND p.tenant_id = d.tenant_id AND p.deleted_at IS NULL AND p.enabled = TRUE
		  JOIN policy_rules r
		    ON r.policy_id = p.id
		 WHERE d.id = ?
		   AND (
		         (r.source_device_id IS NULL AND r.source_group_id IS NULL)
		      OR  r.source_device_id = d.id
		      OR  r.source_group_id = g.id
		      OR  r.source_group_id IN (
		            SELECT dgm.group_id
		              FROM device_group_memberships dgm
		             WHERE dgm.device_id = d.id
		          )
		       )
		 ORDER BY FIELD(r.action, 'drop', 'reject', 'accept'), r.dst_bits DESC`,
		deviceID.Bytes())
	if err != nil {
		return nil, fmt.Errorf("policies.GetEffectiveRules: %w", err)
	}
	defer rows.Close()

	var out []Rule
	for rows.Next() {
		var (
			action   string
			dstAddr  []byte
			dstBits  uint8
			protocol string
			portMin  uint16
			portMax  uint16
		)
		if err := rows.Scan(&action, &dstAddr, &dstBits, &protocol, &portMin, &portMax); err != nil {
			return nil, fmt.Errorf("policies.GetEffectiveRules scan: %w", err)
		}
		addr, ok := netip.AddrFromSlice(dstAddr)
		if !ok {
			// A malformed row would otherwise silently widen the
			// ruleset. Skip it loudly rather than emitting a rule we
			// can't reason about.
			continue
		}
		// 0001 stores IPv4 in 16-byte mapped form. Unmap so the prefix
		// length lines up with the stored dst_bits (which counts v4 bits
		// for v4 rules, not the 96-bit mapped offset).
		addr = addr.Unmap()
		if int(dstBits) > addr.BitLen() {
			continue
		}
		prefix := netip.PrefixFrom(addr, int(dstBits)).Masked()
		if !prefix.IsValid() {
			continue
		}
		out = append(out, Rule{
			Action:   action,
			Dst:      prefix,
			Protocol: protocol,
			PortMin:  portMin,
			PortMax:  portMax,
		})
	}
	return out, rows.Err()
}
