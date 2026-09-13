-- Reverse of 0011_route_scope.up.sql.
--
-- Any policy set to 'full' silently reverts to split-tunnel behaviour on
-- the next client refresh: apps regain direct internet access. That is a
-- loosening, so re-check lockdown policies after a rollback.

ALTER TABLE policies
  DROP COLUMN route_scope;
