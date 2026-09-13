-- Reverse of 0009_node_agent_auth.up.sql.
--
-- Dropping the token hashes is destructive: every gateway agent loses its
-- credential and must be re-issued one after a re-migrate. That's the
-- intended semantic for a down-migration (return to the pre-0.10.0 world
-- where peer sync used the unauthenticated dev endpoint), but it is worth
-- stating plainly because the failure mode is silent — gateways keep
-- running on their last-applied ruleset and just stop receiving updates.

DROP INDEX ix_nodes_agent_token ON nodes;

ALTER TABLE nodes
  DROP COLUMN agent_synced_at,
  DROP COLUMN agent_token_set_at,
  DROP COLUMN agent_token_hash;
