-- =============================================================================
-- Migration 0009 — node agent authentication (0.10.0)
--
-- Closes the hole where the gateway's peer-sync sidecar polled
-- `GET /admin/dev/peers` with NO authentication. That endpoint was gated
-- behind `EnableDevAdmin` and bound to the docker-internal network, which
-- meant a production deploy had to choose between "leave an unauthenticated
-- endpoint reachable" and "turn it off and lose peer sync entirely".
--
-- The replacement is `GET /node/peers`, authenticated by a per-node bearer
-- token. We store only the SHA-256 of the token, never the token itself —
-- a controller DB dump must not yield working gateway credentials.
--
-- Token lifecycle:
--   1. Operator runs `aidotvpn-ctl node issue-token --node <hostname>`
--      (cmd/migrate ships the helper; see docs/gateway-deployment.md).
--   2. Controller stores SHA-256(token) here and prints the token once.
--   3. Operator writes it into the gateway host's /etc/aidotvpn/agent.env.
--   4. Rotation = issue a new token; the old hash is overwritten and the
--      old token stops working on the next request.
-- =============================================================================

ALTER TABLE nodes
  ADD COLUMN agent_token_hash  BINARY(32)   NULL AFTER status,
  ADD COLUMN agent_token_set_at TIMESTAMP(6) NULL AFTER agent_token_hash,
  -- Last time this node successfully pulled /node/peers. Distinct from
  -- last_seen_at, which the data-plane telemetry path owns; a gateway can
  -- be syncing policy fine while its WG telemetry is broken, and we want
  -- to see those two failures separately in the console.
  ADD COLUMN agent_synced_at   TIMESTAMP(6) NULL AFTER agent_token_set_at;

-- Lookup is by token hash on every sync poll, so it needs an index.
-- Not UNIQUE: two nodes could in principle be issued the same token by a
-- broken provisioning script, and we'd rather serve both than throw a
-- duplicate-key error at request time. The handler rejects ambiguous
-- matches explicitly instead.
CREATE INDEX ix_nodes_agent_token ON nodes (agent_token_hash);
