-- =============================================================================
-- Migration 0003 — Phase 8 policy management
--
-- Adds the missing pieces to drive WireGuard split-tunnel policy
-- end-to-end (controller → data-node → Android client):
--
--   1) devices.policy_id  — each device may be assigned to a policy
--   2) policy_allowed_ips — the AllowedIPs CIDRs that the policy permits
--
-- Why a separate table from `policy_rules`:
--
--   `policy_rules` was designed in 0001 for full L4 policy (action,
--   protocol, port range, src/dst). That's overkill for the immediate
--   need of "which destination CIDRs should this device's tunnel
--   carry?", which is a flat list. Mixing the two would force every
--   AllowedIPs read to project away the L4 fields. Keeping them
--   separate also lets Phase 8b (firewall-style policy) evolve the L4
--   shape without touching the AllowedIPs table.
-- =============================================================================

ALTER TABLE devices
  ADD COLUMN policy_id BINARY(16) NULL AFTER status,
  ADD KEY ix_devices_policy (policy_id),
  ADD CONSTRAINT fk_devices_policy
    FOREIGN KEY (policy_id) REFERENCES policies (id);

CREATE TABLE policy_allowed_ips (
  id          BINARY(16)    NOT NULL,
  policy_id   BINARY(16)    NOT NULL,
  -- Text-form CIDR. We accept both IPv4 ("10.10.0.0/16") and IPv6
  -- ("2001:db8::/32") in the same column; Go validates on write. Length
  -- 64 covers IPv6 + scope-id without padding.
  cidr        VARCHAR(64)   NOT NULL,
  description VARCHAR(255)  NULL,
  created_at  TIMESTAMP(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  PRIMARY KEY (id),
  UNIQUE KEY uq_policy_cidr (policy_id, cidr),
  KEY ix_pai_policy (policy_id),
  CONSTRAINT fk_pai_policy
    FOREIGN KEY (policy_id) REFERENCES policies (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
