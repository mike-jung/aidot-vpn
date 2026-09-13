-- 0002_attestation.down.sql

ALTER TABLE attestation_records
  DROP INDEX ix_attest_fp,
  DROP COLUMN security_level,
  DROP COLUMN play_integrity_verdict,
  DROP COLUMN cert_fingerprint;

DROP TABLE IF EXISTS attestation_challenges;
DROP TABLE IF EXISTS device_attestations_allowlist;
DROP TABLE IF EXISTS tenant_kem_keys;

ALTER TABLE tenants
  DROP COLUMN require_device_attestation;
