DROP INDEX ix_device_expiry ON devices;
ALTER TABLE devices DROP COLUMN access_expires_at;
ALTER TABLE tenants DROP COLUMN device_expiry_days;
