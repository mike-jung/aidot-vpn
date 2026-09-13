-- AidotVpn initial schema migration (down).
-- Drops in reverse FK dependency order.

SET FOREIGN_KEY_CHECKS = 0;

DROP TABLE IF EXISTS audit_log;
DROP TABLE IF EXISTS policy_rules;
DROP TABLE IF EXISTS policies;
DROP TABLE IF EXISTS sessions;
DROP TABLE IF EXISTS client_certs;
DROP TABLE IF EXISTS attestation_records;
DROP TABLE IF EXISTS device_group_memberships;
DROP TABLE IF EXISTS device_psks;
DROP TABLE IF EXISTS device_keys;
DROP TABLE IF EXISTS devices;
DROP TABLE IF EXISTS node_endpoints;
DROP TABLE IF EXISTS nodes;
DROP TABLE IF EXISTS user_group_memberships;
DROP TABLE IF EXISTS `groups`;
DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS tenants;

SET FOREIGN_KEY_CHECKS = 1;
