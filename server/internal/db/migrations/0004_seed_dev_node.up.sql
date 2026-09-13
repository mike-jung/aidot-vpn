-- =============================================================================
-- Migration 0004 — seed a dev-only WireGuard node + endpoint
--
-- Why this exists:
--
--   The Android (and any other) client receives a peer list during
--   registration. With no rows in `nodes`, that list is empty and the
--   client sees "no node available" when trying to connect. For the
--   default single-tenant dev deploy, a single placeholder node + one
--   wg endpoint is enough to:
--
--     1. Let the client build a complete WireGuard config.
--     2. Bring the tunnel UP locally (the OS-level VpnService tunfd
--        opens, the wg userspace handshake fires UDP packets at the
--        endpoint).
--     3. Expose the absent-data-plane gap as a real handshake timeout
--        rather than a "registered but won't connect" UI state.
--
-- The seeded node DOES NOT have a real WireGuard daemon behind it, so
-- the handshake will never complete in dev. That's fine for the manual
-- demo flow; production deployments override these rows by registering
-- their own data nodes via the gRPC NodeService and these dev rows go
-- unused (real fleets have many nodes; the client picks one of them).
--
-- Public_key value: 32 bytes of zeros. WireGuard treats this as a
-- well-formed-but-non-functional key. Any real node ships an actual
-- generated key during its first SyncPeers call.
-- =============================================================================

-- Default tenant from migration 0001 (UUIDv7 stub seeded at boot).
SET @tenant_id = UNHEX('019650000000700080000000000000A1');

-- Stable IDs derived from the tenant prefix so re-running the migration
-- after a reset produces the same rows (UNIQUE keys would otherwise
-- block).
SET @dev_node_id     = UNHEX('019650000000700080000000000000B1');
SET @dev_endpoint_id = UNHEX('019650000000700080000000000000B2');

INSERT INTO nodes (id, tenant_id, hostname, region, public_key, status)
VALUES (
    @dev_node_id,
    @tenant_id,
    'dev-node-1.aidotvpn.local',
    'dev-local',
    -- Well-formed X25519 public key matching the dev wg0.conf
    -- PrivateKey ON18RsAf+Roxjy3WVo3vdg6mGUCacC+3id3csLYDfkA=.
    -- See infra/wireguard/wg0.conf for the matching private side.
    --
    -- WHY NOT 32 ZERO BYTES: WireGuard's wireguard-go rejects an
    -- all-zero peer public key with "invalid public key" because it's
    -- the curve's identity element — handshake never starts. A real
    -- key whose private side is ALSO present in our wg-data-node
    -- container completes a real handshake.
    UNHEX('F0F5FBC5317DCA5FD87EB4F767BB271D24807D11175545A5C310EA237C875A46'),
    'active'
);

INSERT INTO node_endpoints (id, node_id, mode, public_host, public_port, enabled)
VALUES (
    @dev_endpoint_id,
    @dev_node_id,
    'wg',
    -- 10.0.2.2 is the Android emulator's host-loopback alias. Real
    -- devices on the same LAN need the host's LAN IP — overridable by
    -- swapping this row at run time.
    '10.0.2.2',
    51820,
    TRUE
);
