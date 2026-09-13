-- The last time this device actually spoke to the gateway.
--
-- WireGuard has no "connected" state. It is a silent protocol: peers
-- handshake periodically, and that timestamp is the only evidence a
-- device is alive. Every comparable console shows it — wg-easy, which
-- is about as simple as these tools get, puts it next to every client.
--
-- What we showed instead:
--
--   status        active   ← an admin's decision, true for a phone in a drawer
--   last_seen_at  —        ← when the controller API was last called
--
-- Neither says whether the tunnel carries traffic. The gateway knows,
-- because `wg show` reports it per peer; nothing carried it here.
ALTER TABLE devices
  ADD COLUMN last_handshake_at TIMESTAMP(6) NULL AFTER last_seen_at,
  ADD COLUMN rx_bytes          BIGINT       NULL AFTER last_handshake_at,
  ADD COLUMN tx_bytes          BIGINT       NULL AFTER rx_bytes;
