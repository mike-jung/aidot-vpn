DROP TABLE IF EXISTS admin_recovery_codes;
ALTER TABLE admins DROP COLUMN totp_enabled_at;
ALTER TABLE admins DROP COLUMN totp_secret;
