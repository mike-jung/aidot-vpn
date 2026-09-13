-- Reverse 0003 — drop the policy_allowed_ips table and the device→policy FK.

DROP TABLE IF EXISTS policy_allowed_ips;

ALTER TABLE devices
  DROP FOREIGN KEY fk_devices_policy,
  DROP KEY ix_devices_policy,
  DROP COLUMN policy_id;
