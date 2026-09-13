-- 0008_per_app_split.down.sql
DROP INDEX ix_devices_tenant_appfilter ON devices;
ALTER TABLE devices
  DROP COLUMN app_filter_mode,
  DROP COLUMN app_filter_packages;
