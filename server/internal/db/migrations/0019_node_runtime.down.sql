ALTER TABLE nodes
  DROP COLUMN last_report_at,
  DROP COLUMN wg_backend,
  DROP COLUMN wg_interface_up,
  DROP COLUMN peer_count,
  DROP COLUMN agent_version;
