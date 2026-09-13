-- 0002_attestation.up.sql
--
-- Phase 6/7/Allowlist additions:
--
--  1. tenants.require_device_attestation — if true, only devices whose
--     hardware-attested fingerprint is in `device_attestations` may
--     register. False (the default) keeps the Phase 5b open-enrollment
--     model.
--
--  2. tenants.tenant_kem_public_key — ML-KEM-768 encapsulation key the
--     mobile client uses to establish a PQC-derived shared secret. Paired
--     with tenant_kem_secret_key which lives in a separate table (so a
--     SELECT on tenants doesn't leak the private half).
--
--  3. device_attestations — pre-enrolled hardware fingerprints. Filled
--     out-of-band by an admin (the admin console UI surfaces this in
--     Phase 7's "단말 등록" screen). One row per fingerprint.
--
--  4. attestation_records picks up two new columns to record the
--     verification outcome of each Register/RotateKey: the verdict from
--     Play Integrity (when supplied) and the leaf attestation cert
--     fingerprint (so the audit trail can show "device X attested
--     with chain Y").

ALTER TABLE tenants
  ADD COLUMN require_device_attestation TINYINT(1) NOT NULL DEFAULT 0
    AFTER ipv6_pool_bits;

CREATE TABLE tenant_kem_keys (
  tenant_id           BINARY(16)      NOT NULL,
  algorithm           VARCHAR(32)     NOT NULL DEFAULT 'ml-kem-768',
  public_key          VARBINARY(2048) NOT NULL,
  secret_key          VARBINARY(4096) NOT NULL,
  rotated_at          TIMESTAMP(6)    NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  PRIMARY KEY (tenant_id),
  CONSTRAINT fk_kem_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE device_attestations_allowlist (
  id              BINARY(16)      NOT NULL,
  tenant_id       BINARY(16)      NOT NULL,
  -- SHA-256 of the leaf attestation cert's SubjectPublicKeyInfo.
  -- Stable across Register/RotateKey on the same device.
  fingerprint     BINARY(32)      NOT NULL,
  -- Operator-supplied label so admins can identify rows in the UI.
  label           VARCHAR(128)    NOT NULL DEFAULT '',
  enrolled_at     TIMESTAMP(6)    NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  enrolled_by     BINARY(16)      NULL,
  deleted_at      TIMESTAMP(6)    NULL,
  PRIMARY KEY (id),
  UNIQUE KEY uq_allowlist_fingerprint (tenant_id, fingerprint),
  KEY ix_allowlist_tenant (tenant_id, deleted_at),
  CONSTRAINT fk_allow_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE,
  CONSTRAINT fk_allow_user FOREIGN KEY (enrolled_by) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Track each verification: which attestation challenge we issued, when,
-- and how the device responded. Used both for replay protection (the
-- challenge has a TTL) and for the audit trail.
CREATE TABLE attestation_challenges (
  challenge       BINARY(32)      NOT NULL,
  tenant_id       BINARY(16)      NOT NULL,
  user_id         BINARY(16)      NOT NULL,
  issued_at       TIMESTAMP(6)    NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  consumed_at     TIMESTAMP(6)    NULL,
  PRIMARY KEY (challenge),
  KEY ix_chal_user (user_id, issued_at),
  CONSTRAINT fk_chal_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE,
  CONSTRAINT fk_chal_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Existing attestation_records table: extend with verification outcome.
ALTER TABLE attestation_records
  ADD COLUMN cert_fingerprint BINARY(32) NULL AFTER payload,
  ADD COLUMN play_integrity_verdict VARCHAR(64) NULL AFTER cert_fingerprint,
  ADD COLUMN security_level VARCHAR(32) NULL AFTER play_integrity_verdict,
  ADD INDEX ix_attest_fp (cert_fingerprint);
