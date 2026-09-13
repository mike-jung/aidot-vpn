-- Two-factor for the admin console.
--
-- One password changes VPN policy for an entire hospital: which wards
-- reach which systems, which handsets are trusted, whose access is
-- revoked. Everything else here — argon2id, session expiry, per-address
-- throttling — protects that password, and none of it helps once the
-- password is known.
--
-- TOTP (RFC 6238) rather than SMS or push: it works on a phone with no
-- signal, needs no third party, and every authenticator app already
-- speaks it. The secret is stored as base32 because that is what the
-- otpauth:// URI carries.
ALTER TABLE admins ADD COLUMN totp_secret VARCHAR(64) NULL;
ALTER TABLE admins ADD COLUMN totp_enabled_at TIMESTAMP(6) NULL;

-- Recovery codes, hashed like passwords.
--
-- A lost phone must not mean a locked-out administrator and a hospital
-- that cannot revoke a stolen handset. Single use: consumed rows are
-- deleted, so a code read over someone's shoulder is worth one login
-- that the owner then finds missing.
CREATE TABLE admin_recovery_codes (
  id         BINARY(16)   NOT NULL PRIMARY KEY,
  admin_id   BINARY(16)   NOT NULL,
  code_hash  VARCHAR(255) NOT NULL,
  created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  used_at    TIMESTAMP(6) NULL,
  CONSTRAINT fk_recovery_admin FOREIGN KEY (admin_id) REFERENCES admins(id)
);
