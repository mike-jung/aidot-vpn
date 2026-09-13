-- 0008_per_app_split.up.sql — Phase 8 per-app split tunnel.
--
-- Two new columns on `devices`:
--
--   app_filter_mode      ENUM('off', 'include', 'exclude')
--     'off'     → no per-app filtering (current default behaviour;
--                 every app on the device routes through the tunnel
--                 subject only to AllowedIPs / split-tunnel CIDRs).
--     'include' → ONLY the apps in app_filter_packages route through
--                 the tunnel; everything else uses the underlying
--                 network. Mirrors VpnService.Builder.addAllowedApplication.
--     'exclude' → every app EXCEPT those in app_filter_packages uses
--                 the tunnel. Mirrors VpnService.Builder.addDisallowedApplication.
--
--   app_filter_packages  JSON
--     A JSON array of Android package names, e.g.
--     ["com.acme.intranet", "com.acme.email"].
--     Empty array '[]' is the default and is the only valid value
--     while app_filter_mode = 'off'. The application enforces this
--     invariant (rather than a DB CHECK) because the API never lets
--     a caller set 'off' with non-empty packages.
--
-- iOS / Linux clients ignore these fields for now (Phase 9). Android
-- 14+ supports them via the existing Interface.Builder API, and
-- wireguard-android translates them into VpnService.Builder calls
-- under the hood.
--
-- Backward compatibility: every existing device gets ('off', '[]') —
-- behaviour unchanged unless an admin explicitly sets a filter.
ALTER TABLE devices
  ADD COLUMN app_filter_mode
    ENUM('off', 'include', 'exclude')
    NOT NULL DEFAULT 'off'
    AFTER app_version,
  ADD COLUMN app_filter_packages
    JSON
    NOT NULL DEFAULT '[]';

-- Index on (tenant_id, app_filter_mode) speeds up the admin console's
-- "show me all devices with a filter active" query. Most installations
-- will have most devices on 'off', so this is highly selective.
CREATE INDEX ix_devices_tenant_appfilter
  ON devices (tenant_id, app_filter_mode);
