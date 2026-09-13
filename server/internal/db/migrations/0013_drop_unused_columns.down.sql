-- Reverse of 0013_drop_unused_columns.up.sql.
--
-- Restores the columns as nullable with no data. They held nothing when
-- they were dropped — that was the reason for dropping them — so there
-- is nothing to recover, and a rollback returns the schema's shape
-- without returning any history.
--
-- The sessions foreign key is restored too, so a subsequent re-apply of
-- 0013 finds what it expects to drop.

ALTER TABLE device_group_memberships
  ADD COLUMN added_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6);

ALTER TABLE sessions
  ADD COLUMN endpoint_id BINARY(16) NULL,
  ADD COLUMN started_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6);
ALTER TABLE sessions
  ADD CONSTRAINT fk_sessions_endpoint
    FOREIGN KEY (endpoint_id) REFERENCES node_endpoints (id);
