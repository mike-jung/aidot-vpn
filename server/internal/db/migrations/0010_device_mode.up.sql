-- =============================================================================
-- Migration 0010 — deployment-mode tagging for devices (0.11.0)
--
-- 0.11.0 makes it possible to run the VPN engine in two shapes:
--
--   standalone : the AidotVpn app hosts the VpnService; business apps
--                drive it over AIDL.
--   embedded   : the business app embeds :vpnlib and hosts the
--                VpnService itself (single APK).
--
-- Both register through the same endpoint, and `install_id` is generated
-- per-app-storage. So one physical handset running both shapes registers
-- TWICE: two devices, two WireGuard keypairs, two IP allocations, two
-- policy assignments. Without a mode column the console shows two rows
-- named "SM-S911N" and an admin has no way to tell which is which — nor
-- to notice that the one they carefully scoped is not the one the user
-- actually connects with.
--
-- This does not prevent the duplicate. It cannot: the two apps are
-- separate installs with separate storage, and merging them would mean
-- trusting a client-supplied hardware identifier, which is both
-- unreliable and a privacy problem. What it does is make the duplicate
-- visible and attributable.
-- =============================================================================

ALTER TABLE devices
  ADD COLUMN deployment_mode VARCHAR(16) NOT NULL DEFAULT 'standalone'
    AFTER platform,
  -- The package that hosts the VpnService. For standalone this is always
  -- com.aidotvpn.client.app; for embedded it is the business app. Lets an
  -- admin answer "which app on this phone holds the tunnel?" without
  -- asking the user to read a settings screen aloud over the phone.
  ADD COLUMN host_package VARCHAR(255) NULL AFTER deployment_mode;

-- Surfaces same-user duplicates in the console's device list.
CREATE INDEX ix_devices_user_mode ON devices (user_id, deployment_mode);
