-- Where the device's packets came from, as the gateway saw them: the
-- phone's public address:port. Column 2 of `wg show dump`. Shown in the
-- device detail dialog as 접속 지점; what Tailscale calls the device's
-- public IP.
ALTER TABLE devices ADD COLUMN last_endpoint VARCHAR(64) NULL AFTER tx_bytes;
