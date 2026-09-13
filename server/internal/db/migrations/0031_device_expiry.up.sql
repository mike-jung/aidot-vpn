-- Access expiry: a registration that does not last forever.
--
-- device_keys.expires_at existed since 0001 and nothing ever read it,
-- so an enrolled phone was enrolled for good — including a handset that
-- left with a nurse who changed jobs, until somebody remembered to
-- revoke it. Tailscale's key expiry exists for the same reason: the
-- safe default for a credential is that it runs out.
--
-- Per tenant, in days, rather than a fixed constant: a ward handset and
-- a contractor's laptop want different answers, and zero means "do not
-- expire" for installations that manage the lifetime some other way.
ALTER TABLE tenants ADD COLUMN device_expiry_days INT NOT NULL DEFAULT 0;

-- The device's own deadline, so extending one phone does not require
-- changing the tenant default. NULL means "use the tenant setting".
ALTER TABLE devices ADD COLUMN access_expires_at TIMESTAMP(6) NULL AFTER status;
CREATE INDEX ix_device_expiry ON devices (tenant_id, access_expires_at);
