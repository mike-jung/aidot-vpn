-- AidotVpn initial schema migration (up).
--
-- Conventions:
--   * Primary keys are UUIDv7 stored as BINARY(16) (16 bytes, k-sortable,
--     leading 48 bits = unix-ms-timestamp; gives clustered-index locality
--     similar to AUTO_INCREMENT while staying globally unique).
--   * All timestamps are TIMESTAMP(6) (microsecond precision) UTC.
--   * Soft delete via `deleted_at`; queries filter `deleted_at IS NULL`.
--   * `tenant_id` is on every major table for multi-tenant isolation;
--     the default tenant is seeded at the end of this migration.
--   * Foreign keys use ON DELETE RESTRICT by default — destructive cascades
--     come later via explicit cleanup procedures.
--   * Engine = InnoDB, charset = utf8mb4, collation = utf8mb4_unicode_ci
--     (set at the schema level by the connection; explicit on each table
--     for safety).

SET NAMES utf8mb4;
SET time_zone = '+00:00';

-- =============================================================================
-- tenants  -- top-level isolation boundary.
-- =============================================================================
CREATE TABLE tenants (
  id              BINARY(16)      NOT NULL,
  slug            VARCHAR(64)     NOT NULL,
  display_name    VARCHAR(255)    NOT NULL,
  -- A tenant owns one or more WireGuard IPv4/IPv6 pools. Stored as
  -- prefix + length; expanded by Go application code.
  ipv4_pool_addr  VARBINARY(4)    NOT NULL,
  ipv4_pool_bits  TINYINT UNSIGNED NOT NULL,
  ipv6_pool_addr  VARBINARY(16)   NULL,
  ipv6_pool_bits  TINYINT UNSIGNED NULL,
  created_at      TIMESTAMP(6)    NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  updated_at      TIMESTAMP(6)    NOT NULL DEFAULT CURRENT_TIMESTAMP(6)
                                 ON UPDATE CURRENT_TIMESTAMP(6),
  deleted_at      TIMESTAMP(6)    NULL,
  PRIMARY KEY (id),
  UNIQUE KEY uq_tenants_slug (slug),
  KEY ix_tenants_deleted_at (deleted_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- =============================================================================
-- users  -- mirror of Keycloak subjects. Source of truth lives in Keycloak;
-- this table caches the subject + display fields and lets us own foreign keys.
-- =============================================================================
CREATE TABLE users (
  id              BINARY(16)      NOT NULL,
  tenant_id       BINARY(16)      NOT NULL,
  -- Keycloak `sub` claim (UUID string); we store as text to avoid
  -- assumptions about Keycloak's internal format.
  kc_subject      VARCHAR(64)     NOT NULL,
  email           VARCHAR(255)    NOT NULL,
  display_name    VARCHAR(255)    NULL,
  status          ENUM('active','suspended','disabled') NOT NULL DEFAULT 'active',
  last_login_at   TIMESTAMP(6)    NULL,
  created_at      TIMESTAMP(6)    NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  updated_at      TIMESTAMP(6)    NOT NULL DEFAULT CURRENT_TIMESTAMP(6)
                                 ON UPDATE CURRENT_TIMESTAMP(6),
  deleted_at      TIMESTAMP(6)    NULL,
  PRIMARY KEY (id),
  UNIQUE KEY uq_users_tenant_kcsub (tenant_id, kc_subject),
  UNIQUE KEY uq_users_tenant_email (tenant_id, email),
  KEY ix_users_status (tenant_id, status, deleted_at),
  CONSTRAINT fk_users_tenant
    FOREIGN KEY (tenant_id) REFERENCES tenants (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- =============================================================================
-- groups  -- ACL groups for users and devices.
-- =============================================================================
CREATE TABLE `groups` (
  id              BINARY(16)      NOT NULL,
  tenant_id       BINARY(16)      NOT NULL,
  name            VARCHAR(128)    NOT NULL,
  description     VARCHAR(512)    NULL,
  created_at      TIMESTAMP(6)    NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  updated_at      TIMESTAMP(6)    NOT NULL DEFAULT CURRENT_TIMESTAMP(6)
                                 ON UPDATE CURRENT_TIMESTAMP(6),
  deleted_at      TIMESTAMP(6)    NULL,
  PRIMARY KEY (id),
  UNIQUE KEY uq_groups_tenant_name (tenant_id, name),
  CONSTRAINT fk_groups_tenant
    FOREIGN KEY (tenant_id) REFERENCES tenants (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE user_group_memberships (
  user_id         BINARY(16)      NOT NULL,
  group_id        BINARY(16)      NOT NULL,
  added_at        TIMESTAMP(6)    NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  PRIMARY KEY (user_id, group_id),
  KEY ix_ugm_group (group_id),
  CONSTRAINT fk_ugm_user  FOREIGN KEY (user_id)  REFERENCES users (id),
  CONSTRAINT fk_ugm_group FOREIGN KEY (group_id) REFERENCES `groups` (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- =============================================================================
-- nodes  -- WireGuard data-plane servers.
-- =============================================================================
CREATE TABLE nodes (
  id              BINARY(16)      NOT NULL,
  tenant_id       BINARY(16)      NOT NULL,
  hostname        VARCHAR(253)    NOT NULL,         -- DNS-style hostname
  region          VARCHAR(64)     NOT NULL,         -- e.g. 'kr-seoul', 'us-west'
  -- Public/peer key the node advertises. WG keys are Curve25519, 32 bytes.
  public_key      BINARY(32)      NOT NULL,
  -- Optional sodium/age-encrypted private key wrapper. Generally we expect the
  -- node to keep the private key locally and only register the pubkey here.
  status          ENUM('provisioning','active','draining','offline','retired')
                                  NOT NULL DEFAULT 'provisioning',
  last_seen_at    TIMESTAMP(6)    NULL,
  created_at      TIMESTAMP(6)    NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  updated_at      TIMESTAMP(6)    NOT NULL DEFAULT CURRENT_TIMESTAMP(6)
                                 ON UPDATE CURRENT_TIMESTAMP(6),
  deleted_at      TIMESTAMP(6)    NULL,
  PRIMARY KEY (id),
  UNIQUE KEY uq_nodes_pubkey (public_key),
  UNIQUE KEY uq_nodes_tenant_hostname (tenant_id, hostname),
  KEY ix_nodes_tenant_status (tenant_id, status, deleted_at),
  CONSTRAINT fk_nodes_tenant
    FOREIGN KEY (tenant_id) REFERENCES tenants (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- =============================================================================
-- node_endpoints  -- listen addresses per node, per protocol mode.
-- One node can serve multiple protocols simultaneously (plain WG, AmneziaWG,
-- Shadowsocks-wrapped, etc.). Clients pick the best one per their environment.
-- =============================================================================
CREATE TABLE node_endpoints (
  id              BINARY(16)      NOT NULL,
  node_id         BINARY(16)      NOT NULL,
  -- Logical mode advertised to clients.
  mode            ENUM('wg','wg_junk','amneziawg','shadowsocks_tcp','shadowsocks_ws')
                                  NOT NULL,
  -- Public address (IP or hostname) and port to dial from clients.
  public_host     VARCHAR(253)    NOT NULL,
  public_port     SMALLINT UNSIGNED NOT NULL,
  -- Mode-specific opaque parameters (e.g. AmneziaWG H1..H4 ranges, SS cipher,
  -- junk-packet config). Stored as JSON for forward compatibility.
  params          JSON            NULL,
  enabled         BOOLEAN         NOT NULL DEFAULT TRUE,
  created_at      TIMESTAMP(6)    NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  updated_at      TIMESTAMP(6)    NOT NULL DEFAULT CURRENT_TIMESTAMP(6)
                                 ON UPDATE CURRENT_TIMESTAMP(6),
  PRIMARY KEY (id),
  UNIQUE KEY uq_endpoints_node_mode (node_id, mode),
  KEY ix_endpoints_enabled (enabled),
  CONSTRAINT fk_endpoints_node
    FOREIGN KEY (node_id) REFERENCES nodes (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- =============================================================================
-- devices  -- per-user mobile devices that can connect.
-- =============================================================================
CREATE TABLE devices (
  id              BINARY(16)      NOT NULL,
  tenant_id       BINARY(16)      NOT NULL,
  user_id         BINARY(16)      NOT NULL,
  -- Stable client-generated identifier persisted on the device. Used to
  -- detect re-installs and recover keys instead of treating every fresh
  -- pubkey as a new device.
  install_id      CHAR(36)        NOT NULL,         -- UUID string
  display_name    VARCHAR(128)    NOT NULL,         -- "Alice's Pixel 9"
  platform        ENUM('android','ios','linux','macos','windows','other')
                                  NOT NULL DEFAULT 'other',
  os_version      VARCHAR(64)     NULL,
  app_version     VARCHAR(64)     NULL,
  status          ENUM('pending_attest','active','suspended','revoked')
                                  NOT NULL DEFAULT 'pending_attest',
  last_seen_at    TIMESTAMP(6)    NULL,
  created_at      TIMESTAMP(6)    NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  updated_at      TIMESTAMP(6)    NOT NULL DEFAULT CURRENT_TIMESTAMP(6)
                                 ON UPDATE CURRENT_TIMESTAMP(6),
  deleted_at      TIMESTAMP(6)    NULL,
  PRIMARY KEY (id),
  UNIQUE KEY uq_devices_user_install (user_id, install_id),
  KEY ix_devices_tenant_status (tenant_id, status, deleted_at),
  KEY ix_devices_user (user_id),
  CONSTRAINT fk_devices_tenant FOREIGN KEY (tenant_id) REFERENCES tenants (id),
  CONSTRAINT fk_devices_user   FOREIGN KEY (user_id)   REFERENCES users (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- =============================================================================
-- device_keys  -- WG pubkey history per device.
-- The "current" key is the most recently activated row with revoked_at IS NULL.
-- We keep history so audit trails can resolve old peers seen on the wire.
-- =============================================================================
CREATE TABLE device_keys (
  id              BINARY(16)      NOT NULL,
  device_id       BINARY(16)      NOT NULL,
  public_key      BINARY(32)      NOT NULL,         -- Curve25519
  -- Allocated VPN address(es) for this key.
  ipv4_addr       VARBINARY(4)    NULL,
  ipv6_addr       VARBINARY(16)   NULL,
  activated_at    TIMESTAMP(6)    NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  expires_at      TIMESTAMP(6)    NULL,             -- NULL = no auto-rotate
  revoked_at      TIMESTAMP(6)    NULL,             -- non-null => no longer in use
  PRIMARY KEY (id),
  UNIQUE KEY uq_device_keys_pubkey (public_key),
  KEY ix_device_keys_device (device_id, revoked_at),
  KEY ix_device_keys_ipv4 (ipv4_addr),
  CONSTRAINT fk_device_keys_device
    FOREIGN KEY (device_id) REFERENCES devices (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- =============================================================================
-- device_psks  -- pre-shared key history per device.
-- WG PSKs add an extra layer beyond the X25519 ECDH; in our system they
-- carry the post-quantum hybrid contribution (ML-KEM-derived shared secret).
-- =============================================================================
CREATE TABLE device_psks (
  id              BINARY(16)      NOT NULL,
  device_key_id   BINARY(16)      NOT NULL,         -- which key this PSK pairs with
  psk             BINARY(32)      NOT NULL,
  source          ENUM('classical','pqc_hybrid','manual') NOT NULL DEFAULT 'classical',
  -- Free-form metadata about how the PSK was derived (e.g. ML-KEM ciphertext
  -- digest used during establishment). Useful for audit.
  derivation_meta JSON            NULL,
  activated_at    TIMESTAMP(6)    NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  expires_at      TIMESTAMP(6)    NULL,
  revoked_at      TIMESTAMP(6)    NULL,
  PRIMARY KEY (id),
  KEY ix_psks_device_key (device_key_id, revoked_at),
  CONSTRAINT fk_psks_device_key
    FOREIGN KEY (device_key_id) REFERENCES device_keys (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- =============================================================================
-- device_group_memberships
-- =============================================================================
CREATE TABLE device_group_memberships (
  device_id       BINARY(16)      NOT NULL,
  group_id        BINARY(16)      NOT NULL,
  added_at        TIMESTAMP(6)    NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  PRIMARY KEY (device_id, group_id),
  KEY ix_dgm_group (group_id),
  CONSTRAINT fk_dgm_device FOREIGN KEY (device_id) REFERENCES devices (id),
  CONSTRAINT fk_dgm_group  FOREIGN KEY (group_id)  REFERENCES `groups` (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- =============================================================================
-- attestation_records  -- Play Integrity / App Attest verdicts.
-- One row per verification check. Devices in 'pending_attest' need at least
-- one row with verdict='ok' before being moved to 'active'.
-- =============================================================================
CREATE TABLE attestation_records (
  id              BINARY(16)      NOT NULL,
  device_id       BINARY(16)      NOT NULL,
  source          ENUM('play_integrity','app_attest','none') NOT NULL,
  verdict         ENUM('ok','warning','fail','error') NOT NULL,
  -- Decoded JWS payload (Play Integrity) or attestation object (App Attest).
  -- Stored for audit. Limited to 64KB; larger payloads should be summarised.
  payload         JSON            NULL,
  -- Reasons / fields that caused a non-ok verdict.
  notes           VARCHAR(2048)   NULL,
  verified_at     TIMESTAMP(6)    NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  PRIMARY KEY (id),
  KEY ix_attest_device_time (device_id, verified_at),
  CONSTRAINT fk_attest_device
    FOREIGN KEY (device_id) REFERENCES devices (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- =============================================================================
-- client_certs  -- short-lived mTLS certificates issued to devices.
-- The CA is held by the controller; we record only the issued cert metadata
-- and a SHA-256 fingerprint, never the private key.
-- =============================================================================
CREATE TABLE client_certs (
  id              BINARY(16)      NOT NULL,
  device_id       BINARY(16)      NOT NULL,
  serial          BINARY(20)      NOT NULL,         -- raw cert serial number
  fingerprint_sha256 BINARY(32)   NOT NULL,
  not_before      TIMESTAMP(6)    NOT NULL,
  not_after       TIMESTAMP(6)    NOT NULL,
  revoked_at      TIMESTAMP(6)    NULL,
  revocation_reason VARCHAR(128)  NULL,
  PRIMARY KEY (id),
  UNIQUE KEY uq_certs_serial (serial),
  UNIQUE KEY uq_certs_fp (fingerprint_sha256),
  KEY ix_certs_device (device_id, revoked_at),
  CONSTRAINT fk_certs_device
    FOREIGN KEY (device_id) REFERENCES devices (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- =============================================================================
-- sessions  -- active VPN sessions. Updated by data-node heartbeats.
-- =============================================================================
CREATE TABLE sessions (
  id              BINARY(16)      NOT NULL,
  device_key_id   BINARY(16)      NOT NULL,
  node_id         BINARY(16)      NOT NULL,
  endpoint_id     BINARY(16)      NULL,             -- which mode was used
  -- Last successful WG handshake from the data-node's perspective.
  last_handshake_at TIMESTAMP(6)  NULL,
  rx_bytes        BIGINT UNSIGNED NOT NULL DEFAULT 0,
  tx_bytes        BIGINT UNSIGNED NOT NULL DEFAULT 0,
  -- Public client IP as seen by the data node (post-NAT). Stored for the
  -- shortest possible window the operator's policy requires; production
  -- deployments may NULL this column for no-log policies.
  client_ip       VARBINARY(16)   NULL,
  started_at      TIMESTAMP(6)    NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  ended_at        TIMESTAMP(6)    NULL,
  PRIMARY KEY (id),
  KEY ix_sessions_device_key (device_key_id, ended_at),
  KEY ix_sessions_node (node_id, ended_at),
  CONSTRAINT fk_sessions_devkey  FOREIGN KEY (device_key_id) REFERENCES device_keys (id),
  CONSTRAINT fk_sessions_node    FOREIGN KEY (node_id)       REFERENCES nodes (id),
  CONSTRAINT fk_sessions_endpoint FOREIGN KEY (endpoint_id)  REFERENCES node_endpoints (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- =============================================================================
-- policies  -- group-based ACL policies that govern what an attached device
-- is allowed to reach. Rules are stored separately for query convenience.
-- =============================================================================
CREATE TABLE policies (
  id              BINARY(16)      NOT NULL,
  tenant_id       BINARY(16)      NOT NULL,
  name            VARCHAR(128)    NOT NULL,
  description     VARCHAR(1024)   NULL,
  enabled         BOOLEAN         NOT NULL DEFAULT TRUE,
  -- Higher number wins on conflict. We deliberately make precedence explicit
  -- rather than relying on ordering of inserts.
  precedence      INT             NOT NULL DEFAULT 100,
  created_at      TIMESTAMP(6)    NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  updated_at      TIMESTAMP(6)    NOT NULL DEFAULT CURRENT_TIMESTAMP(6)
                                 ON UPDATE CURRENT_TIMESTAMP(6),
  deleted_at      TIMESTAMP(6)    NULL,
  PRIMARY KEY (id),
  UNIQUE KEY uq_policies_tenant_name (tenant_id, name),
  KEY ix_policies_enabled (tenant_id, enabled, deleted_at),
  CONSTRAINT fk_policies_tenant
    FOREIGN KEY (tenant_id) REFERENCES tenants (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- A rule in the form: {action} packets from {source_group} to {dst_cidr,
-- dst_ports, protocol}. Either source_group or source_device is set, not
-- both. Empty source_* means "any device in the policy's tenant".
CREATE TABLE policy_rules (
  id              BINARY(16)      NOT NULL,
  policy_id       BINARY(16)      NOT NULL,
  action          ENUM('accept','reject','drop') NOT NULL,
  source_group_id BINARY(16)      NULL,
  source_device_id BINARY(16)     NULL,
  -- Destination CIDR (always 16 bytes; v4 is left-padded mapped form).
  dst_addr        VARBINARY(16)   NOT NULL,
  dst_bits        TINYINT UNSIGNED NOT NULL,
  -- Layer 4. NULL means any.
  protocol        ENUM('any','tcp','udp','icmp','icmpv6') NOT NULL DEFAULT 'any',
  dst_port_min    SMALLINT UNSIGNED NULL,
  dst_port_max    SMALLINT UNSIGNED NULL,
  PRIMARY KEY (id),
  KEY ix_rules_policy (policy_id),
  KEY ix_rules_src_group (source_group_id),
  KEY ix_rules_src_device (source_device_id),
  CONSTRAINT fk_rules_policy   FOREIGN KEY (policy_id)        REFERENCES policies (id) ON DELETE CASCADE,
  CONSTRAINT fk_rules_src_grp  FOREIGN KEY (source_group_id)  REFERENCES `groups` (id),
  CONSTRAINT fk_rules_src_dev  FOREIGN KEY (source_device_id) REFERENCES devices (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- =============================================================================
-- audit_log  -- tamper-evident, hash-chained audit log.
--
-- Each row stores SHA-256 of (prev_hash || canonical_serialisation(entry));
-- a missing or modified row breaks the chain. The Go layer is responsible
-- for computing canonical JSON.
-- =============================================================================
CREATE TABLE audit_log (
  -- Auto-increment integer purely for chain ordering. The chain integrity
  -- depends on prev_hash, not on this id.
  seq             BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  id              BINARY(16)      NOT NULL,
  tenant_id       BINARY(16)      NOT NULL,
  -- Subject performing the action: a user, device, or system component.
  actor_kind      ENUM('user','device','node','system') NOT NULL,
  actor_id        BINARY(16)      NULL,             -- NULL when actor_kind='system'
  action          VARCHAR(128)    NOT NULL,         -- e.g. 'device.register', 'policy.update'
  target_kind     VARCHAR(64)     NULL,             -- e.g. 'device', 'policy'
  target_id       BINARY(16)      NULL,
  -- Structured details. The Go layer canonicalises this before hashing.
  details         JSON            NULL,
  prev_hash       BINARY(32)      NULL,             -- NULL on first row
  hash            BINARY(32)      NOT NULL,
  occurred_at     TIMESTAMP(6)    NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  PRIMARY KEY (seq),
  UNIQUE KEY uq_audit_id (id),
  KEY ix_audit_tenant_time (tenant_id, occurred_at),
  KEY ix_audit_target (target_kind, target_id, occurred_at),
  CONSTRAINT fk_audit_tenant
    FOREIGN KEY (tenant_id) REFERENCES tenants (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- =============================================================================
-- Seed: a default tenant for single-tenant deployments.
-- The UUID below is a fixed UUIDv7 so dev environments are reproducible.
-- =============================================================================
-- The UUID below is a fixed UUIDv7 (timestamp 2025-04-26, version=7,
-- variant=10b) so dev environments are reproducible across machines.
INSERT INTO tenants (id, slug, display_name, ipv4_pool_addr, ipv4_pool_bits, ipv6_pool_addr, ipv6_pool_bits)
VALUES (
  UNHEX('019650000000700080000000000000A1'),
  'default',
  'Default Tenant',
  UNHEX('0A4E0000'),                            -- 10.78.0.0
  16,
  UNHEX('FD5E7C2AD8E100000000000000000000'),    -- fd5e:7c2a:d8e1::
  48
);
