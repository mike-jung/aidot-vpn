-- =============================================================================
-- Migration 0012 — DNS (0.15.0)
--
-- Closes the gap that made policies painful to operate: internal hostnames
-- did not resolve through the tunnel, so every policy had to be written
-- against raw IPs, and a hospital server changing address meant editing
-- every policy by hand.
--
-- Two separate features live here. They compose but are independent, and
-- conflating them would be a mistake:
--
--   1. DNS PUSH — the client learns which resolver to use inside the
--      tunnel, so an app can look up `emr.hospital.local` at all.
--      (policies.dns_servers, policies.dns_search_domains)
--
--   2. HOSTNAME POLICIES — an admin writes `emr.hospital.local` instead
--      of `10.10.5.20/32`, and the controller keeps the resolved address
--      current on their behalf.
--      (policy_hostnames, policy_hostname_resolutions)
--
-- You can want either without the other. Hostname policies work fine with
-- no DNS push (the controller resolves; the device only ever sees IPs),
-- and DNS push is useful with purely static CIDRs.
-- =============================================================================

-- ---- 1. DNS push ----------------------------------------------------------
--
-- Comma-separated resolver addresses pushed to the client via
-- VpnService.Builder.addDnsServer.
--
-- IMPORTANT operational note, recorded here because it is the most likely
-- way to break a deployment: on Android, a VPN's DNS servers apply to
-- every app on the VPN network, NOT only to traffic matching the tunnel's
-- routes. So with app_filter_mode = 'off' and route_scope = 'policy'
-- (a split tunnel over the whole device), pushing an internal-only
-- resolver captures ALL of the device's DNS — and if that resolver
-- cannot answer public names, the device loses internet name resolution
-- while appearing to have connectivity.
--
-- Safe combinations:
--   * app_filter_mode = 'include'  → only the listed apps use the VPN
--     network, so only their DNS goes to the internal resolver. Clean.
--   * route_scope = 'full'         → nothing else is reachable anyway.
--   * an internal resolver that forwards public queries upstream.
--
-- The controller warns on the unsafe combination rather than refusing it;
-- some sites genuinely do run a forwarding resolver.
ALTER TABLE policies
  ADD COLUMN dns_servers        VARCHAR(255) NULL AFTER route_scope,
  ADD COLUMN dns_search_domains VARCHAR(512) NULL AFTER dns_servers;

-- ---- 2. Hostname policies -------------------------------------------------

CREATE TABLE policy_hostnames (
  id            BINARY(16)   NOT NULL,
  policy_id     BINARY(16)   NOT NULL,
  hostname      VARCHAR(253) NOT NULL,
  description   VARCHAR(255) NULL,

  -- guard_cidr bounds what a resolution may return.
  --
  -- Hostname policies trade explicit, auditable IPs for convenience, and
  -- that trade has a real cost: whoever controls the DNS answer controls
  -- the ACL. A compromised or spoofed internal resolver could point
  -- `emr.hospital.local` at any address and the gateway would faithfully
  -- permit it.
  --
  -- The guard is the mitigation. Set it to the hospital's server range
  -- (e.g. 10.10.0.0/16) and a resolution outside that range is discarded
  -- with a loud log rather than silently widening access. NULL means no
  -- guard, which we allow but the console marks as unsafe.
  guard_cidr    VARCHAR(64)  NULL,

  created_at    TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  PRIMARY KEY (id),
  UNIQUE KEY uq_policy_hostname (policy_id, hostname),
  CONSTRAINT fk_hostnames_policy
    FOREIGN KEY (policy_id) REFERENCES policies (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Resolved addresses, refreshed by the controller's resolver loop.
--
-- Kept in a separate table rather than a column on policy_hostnames
-- because a name legitimately resolves to several addresses, and because
-- we need per-address last_seen_at to expire them individually.
CREATE TABLE policy_hostname_resolutions (
  hostname_id   BINARY(16)   NOT NULL,
  addr          VARBINARY(16) NOT NULL,
  bits          TINYINT UNSIGNED NOT NULL,

  first_seen_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),

  -- last_seen_at drives expiry. An address that stops appearing in DNS
  -- answers is NOT dropped immediately: a device holding an open session
  -- would lose access mid-use on a routine DNS rotation, and a transient
  -- resolver failure would revoke everything at once. It is kept for a
  -- grace window (see RESOLUTION_GRACE in the resolver) and then pruned.
  last_seen_at  TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6)
                             ON UPDATE CURRENT_TIMESTAMP(6),

  PRIMARY KEY (hostname_id, addr),
  KEY ix_resolutions_last_seen (last_seen_at),
  CONSTRAINT fk_resolutions_hostname
    FOREIGN KEY (hostname_id) REFERENCES policy_hostnames (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
