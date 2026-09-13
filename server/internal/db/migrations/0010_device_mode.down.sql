-- Reverse of 0010_device_mode.up.sql.
--
-- Safe to roll back: the columns are descriptive only. Nothing in the
-- enforcement path (policy resolution, nftables rendering, peer sync)
-- reads them, so dropping them narrows what the console can display but
-- does not change which traffic is permitted.

DROP INDEX ix_devices_user_mode ON devices;

ALTER TABLE devices
  DROP COLUMN host_package,
  DROP COLUMN deployment_mode;
