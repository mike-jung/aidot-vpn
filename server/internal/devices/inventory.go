package devices

import (
	"context"
	"database/sql"
	"encoding/base64"
	"fmt"
	"net"
	"time"

	"github.com/aidotvpn/server/internal/domain"
)

// Device inventory — what an admin needs to answer a question about one
// handset without opening a database client.
//
// ## What the fields are for
//
// The list showed name, platform, status, app version, filter and last
// seen. Each is true and none of them answers the questions that get
// asked:
//
//	"10.10.0.7 hit the EMR at 3am — whose phone is that?"
//	  → the assigned VPN address. This is the join key between a
//	    firewall log and a person, and it was the one field not exposed
//	    anywhere in the console. Without it an admin correlates by
//	    hand against the database.
//
//	"why can this device reach the EMR?"
//	  → the bound policy, by name. `policy_bound: true` says a policy
//	    exists; it does not say which, and "which" is the question when
//	    something reaches more than it should.
//
//	"is this thing still alive?"
//	  → last seen, and key expiry. A device that has not checked in for
//	    a month and a key expiring tomorrow are different problems and
//	    the list conflated them into "active".
//
// Deliberately not collected: public IP, geolocation, per-connection
// logs. They are what a fleet console usually adds next and each is a
// standing record of where a nurse physically is. The tenant boundary
// here is a hospital; that data has a different legal weight than
// "which policy applies", and nothing in the product needs it.
type DeviceInventory struct {
	Device

	// The VPN address currently assigned, from the active key.
	IPv4      string
	IPv6      string
	PublicKey string

	// Bound policy, resolved to a name.
	PolicyID   *domain.ID
	PolicyName string

	// Active key lifecycle. Expiry drives the "rotate soon" warning.
	KeyActivatedAt *time.Time
	KeyExpiresAt   *time.Time

	// Owner, for a tenant list where devices belong to different people.
	OwnerEmail string

	// The last time this device actually spoke to the gateway.
	//
	// WireGuard has no connected state; this timestamp is the evidence.
	// Status says what an admin decided and is true for a phone in a
	// drawer.
	LastHandshakeAt *time.Time
	RxBytes         *int64
	LastEndpoint    string
	Model           string
	// Whether the policy is the device's own rather than its group's —
	// the console shows the source, since with groups "why can this
	// phone reach that" needs both the policy and where it came from.
	PolicyDirect bool
	// When this device stops being handed to the gateway. nil = never.
	AccessExpiresAt *time.Time
	OSSdk           int
	PostureBlocked  bool
	GroupID         *domain.ID
	GroupName       string
	TxBytes         *int64

	// Reaching the gateway through the relay rather than directly.
	ViaRelay *bool
}

// ListInventory returns a tenant's devices with the fields an admin
// needs, in one query rather than N+1 lookups from the console.
func (s *Service) ListInventory(ctx context.Context, tenantID domain.ID) ([]DeviceInventory, error) {
	if tenantID.IsZero() {
		tenantID = s.tenantID
	}

	// LEFT JOINs throughout: a device with no active key, no policy or no
	// user is a real state — it is what a freshly registered, unbound
	// device looks like — and an inner join would hide exactly the rows
	// an admin is looking for.
	rows, err := s.db.QueryContext(ctx, `
		SELECT d.id, d.tenant_id, d.user_id, d.install_id, d.display_name,
		       d.platform, d.os_version, d.app_version, d.model, d.status,
		       d.last_seen_at, d.last_handshake_at, d.rx_bytes, d.tx_bytes, d.last_endpoint,
		       d.via_relay,
		       d.created_at,
		       d.app_filter_mode, d.app_filter_packages,
		       d.deployment_mode, COALESCE(d.host_package, ''),
		       dk.ipv4_addr, dk.ipv6_addr, dk.activated_at, dk.expires_at, dk.public_key,
		       p.id, p.name, d.group_id, g.name, d.policy_id AS own_policy,
		       d.access_expires_at, d.os_sdk, t.min_os_sdk,
		       COALESCE(u.email, '')
		FROM devices d
		LEFT JOIN device_keys dk
		       ON dk.device_id = d.id AND dk.revoked_at IS NULL
		LEFT JOIN device_groups g ON g.id = d.group_id AND g.tenant_id = d.tenant_id AND g.deleted_at IS NULL
		LEFT JOIN policies p
		       ON p.id = COALESCE(d.policy_id, g.policy_id) AND p.tenant_id = d.tenant_id AND p.deleted_at IS NULL
		LEFT JOIN users u ON u.id = d.user_id
		JOIN tenants t ON t.id = d.tenant_id
		WHERE d.tenant_id = ? AND d.deleted_at IS NULL
		ORDER BY d.created_at DESC`, tenantID.Bytes())
	if err != nil {
		return nil, fmt.Errorf("ListInventory: %w", err)
	}
	defer rows.Close()

	var out []DeviceInventory
	for rows.Next() {
		var (
			inv                DeviceInventory
			idB, tenB, userB   []byte
			polB, pkgs         []byte
			ipv4, ipv6         []byte
			lastSeen           sql.NullTime
			lastHandshake      sql.NullTime
			rxBytes, txBytes   sql.NullInt64
			viaRelay           sql.NullBool
			lastEndpoint       sql.NullString
			pubKey             []byte
			activated, expires sql.NullTime
			polName            sql.NullString
			osVer, appVer      sql.NullString
			model              sql.NullString
			groupB             []byte
			polOwnB            []byte
			accessExp          sql.NullTime
			osSdk              sql.NullInt64
			minSdk             int
			groupNm            sql.NullString
			hostPkg            string
		)
		if err := rows.Scan(&idB, &tenB, &userB, &inv.InstallID, &inv.DisplayName,
			&inv.Platform, &osVer, &appVer, &model, &inv.Status,
			&lastSeen, &lastHandshake, &rxBytes, &txBytes, &lastEndpoint, &viaRelay, &inv.CreatedAt,
			&inv.AppFilter.Mode, &pkgs,
			&inv.DeploymentMode, &hostPkg,
			&ipv4, &ipv6, &activated, &expires, &pubKey,
			&polB, &polName, &groupB, &groupNm, &polOwnB, &accessExp, &osSdk, &minSdk, &inv.OwnerEmail); err != nil {
			return nil, fmt.Errorf("ListInventory: %w", err)
		}
		_ = inv.ID.Scan(idB)
		_ = inv.TenantID.Scan(tenB)
		_ = inv.UserID.Scan(userB)
		inv.OSVersion = osVer.String
		inv.AppVersion = appVer.String
		if lastSeen.Valid {
			t := lastSeen.Time
			inv.LastSeenAt = &t
		}
		if lastHandshake.Valid {
			t := lastHandshake.Time
			inv.LastHandshakeAt = &t
		}
		if rxBytes.Valid {
			v := rxBytes.Int64
			inv.RxBytes = &v
		}
		if txBytes.Valid {
			v := txBytes.Int64
			inv.TxBytes = &v
		}
		inv.Model = model.String
		inv.PolicyDirect = len(polOwnB) > 0
		inv.OSSdk = int(osSdk.Int64)
		// Blocked by the posture rule: reported a level and it is below
		// the minimum. Not reporting one passes, as the peer query does.
		inv.PostureBlocked = minSdk > 0 && osSdk.Valid && int(osSdk.Int64) < minSdk
		if accessExp.Valid {
			t := accessExp.Time
			inv.AccessExpiresAt = &t
		}
		if len(groupB) > 0 {
			var gid domain.ID
			_ = gid.Scan(groupB)
			inv.GroupID = &gid
			inv.GroupName = groupNm.String
		}
		inv.LastEndpoint = lastEndpoint.String
		if len(pubKey) > 0 {
			inv.PublicKey = base64.StdEncoding.EncodeToString(pubKey)
		}
		if viaRelay.Valid {
			v := viaRelay.Bool
			inv.ViaRelay = &v
		}
		if len(ipv4) == 4 {
			inv.IPv4 = net.IP(ipv4).String()
		}
		if len(ipv6) == 16 {
			inv.IPv6 = net.IP(ipv6).String()
		}
		if activated.Valid {
			t := activated.Time
			inv.KeyActivatedAt = &t
		}
		if expires.Valid {
			t := expires.Time
			inv.KeyExpiresAt = &t
		}
		if len(polB) > 0 {
			var p domain.ID
			if p.Scan(polB) == nil {
				inv.PolicyID = &p
			}
		}
		inv.PolicyName = polName.String
		out = append(out, inv)
	}
	return out, rows.Err()
}

// RecordHandshake stores what the gateway saw for one peer.
//
// Keyed by public key because that is the only identifier `wg show`
// gives. An unknown key updates nothing — a peer removed between the
// gateway reading its interface and the report arriving is ordinary.
func (s *Service) RecordHandshake(
	ctx context.Context,
	publicKeyB64 string,
	at time.Time,
	rx, tx int64,
	viaRelay bool,
	endpoint string,
) error {
	key, err := base64.StdEncoding.DecodeString(publicKeyB64)
	if err != nil {
		return fmt.Errorf("RecordHandshake: bad key: %w", err)
	}
	_, err = s.db.ExecContext(ctx, `
		UPDATE devices d
		  JOIN device_keys k ON k.device_id = d.id AND k.revoked_at IS NULL
		   SET d.last_handshake_at = ?, d.rx_bytes = ?, d.tx_bytes = ?,
		       d.via_relay = ?, d.last_endpoint = ?
		 WHERE k.public_key = ?`, at, rx, tx, viaRelay, endpoint, key)
	if err != nil {
		return fmt.Errorf("RecordHandshake: %w", err)
	}
	return nil
}
