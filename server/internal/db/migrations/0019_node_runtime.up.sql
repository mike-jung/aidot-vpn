-- What the gateway reports about itself.
--
-- The console listed nodes from a seed row and called them 활성. That is
-- a database fact, not a running server: the row exists whether or not
-- WireGuard is up, and a user watched a handset connect, show the key
-- icon, and reach nothing — with every screen claiming the node was
-- fine.
--
-- Two things had to be discoverable and were not:
--
--   1. Is the gateway process alive? (last_report_at)
--   2. Did the tunnel actually come up, and on what? (wg_backend)
--
-- wg_backend matters because wg-quick silently falls back from the
-- kernel module to wireguard-go. Both work; one is much slower. An
-- operator debugging throughput should not have to read container logs
-- to learn which one carried the traffic.
ALTER TABLE nodes
  ADD COLUMN last_report_at  TIMESTAMP(6) NULL AFTER status,
  ADD COLUMN wg_backend      VARCHAR(16)  NULL AFTER last_report_at,
  ADD COLUMN wg_interface_up BOOLEAN      NULL AFTER wg_backend,
  ADD COLUMN peer_count      INT          NULL AFTER wg_interface_up,
  ADD COLUMN agent_version   VARCHAR(32)  NULL AFTER peer_count;
