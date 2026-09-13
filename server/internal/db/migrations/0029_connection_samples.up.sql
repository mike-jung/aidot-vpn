-- Fifteen-minute samples of how many devices were connected.
--
-- devices.last_handshake_at holds one timestamp, so "how many phones
-- were on at 3pm yesterday" cannot be answered from it — the only
-- record of the past is the past itself, and nothing was keeping it.
--
-- The gateway agent reports every fifteen seconds. Storing each report
-- would be 5,760 rows per device per day; folded into fifteen-minute
-- buckets it is 96, so a hundred devices for thirty days is about
-- 290,000 rows. That is a table, not a problem.
--
-- One row per bucket per tenant, upserted: whichever report lands in a
-- bucket updates it, so the sampler needs no schedule of its own and a
-- restart cannot leave a gap wider than the reporting interval.
CREATE TABLE connection_samples (
  tenant_id   BINARY(16)   NOT NULL,
  bucket_at   TIMESTAMP(0) NOT NULL,   -- floor to 15 minutes, UTC
  connected   INT          NOT NULL,   -- devices with a handshake in the last 2 min
  total       INT          NOT NULL,   -- active devices at that moment
  rx_bytes    BIGINT       NOT NULL DEFAULT 0,
  tx_bytes    BIGINT       NOT NULL DEFAULT 0,
  PRIMARY KEY (tenant_id, bucket_at),
  CONSTRAINT fk_sample_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id)
);
