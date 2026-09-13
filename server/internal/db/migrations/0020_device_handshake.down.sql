ALTER TABLE devices
  DROP COLUMN last_handshake_at,
  DROP COLUMN rx_bytes,
  DROP COLUMN tx_bytes;
