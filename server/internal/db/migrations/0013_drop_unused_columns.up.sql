-- =============================================================================
-- Migration 0013 — drop columns nothing reads (0.24.0)
--
-- The wiring check (internal/db/wiring_test.go) has been shrinking a
-- baseline of columns that exist in the schema and are referenced by no
-- Go code. It started at 14 in 0.17.0. Five left in 0.23.0 when
-- client_certs and last_login_at were finally written.
--
-- What remains is a different category. These are not features whose
-- wiring was forgotten — they duplicate something already recorded
-- elsewhere, and wiring them would mean maintaining two sources of truth
-- for one fact. Dropping is the honest resolution.
--
-- Each is listed with what supersedes it, so a future reader can judge
-- the call rather than take it on faith.
--
-- NOT dropped, though also unread: created_at / updated_at /
-- first_seen_at / agent_token_set_at. Those are maintained by the
-- database and read by operators in SQL; "no Go reference" is the
-- expected state for them, not a defect.
-- =============================================================================

-- tenants.slug is NOT dropped.
--
-- The wiring check flagged it because no Go source mentions it, but
-- 0001's own seed INSERT populates it and the column is NOT NULL with a
-- UNIQUE key. Dropping it would break the seed and remove an identifier
-- an operator uses when reading the table by hand — the check's blind
-- spot is that it only looks at Go, not at SQL.
--
-- Left in the baseline with that note instead.

-- users.last_login_at is NOT dropped (wired in 0.23.0).

-- device_group_memberships.added_at — membership is read by (group,
-- device) only. The audit log already records when a membership changed
-- and who changed it, which is the question this column looked like it
-- answered.
ALTER TABLE device_group_memberships DROP COLUMN added_at;

-- sessions.started_at and sessions.endpoint_id.
--
-- started_at: sessions are reported by last_seen_at, which is what a
-- stale-session sweep needs. A start time that nothing updates or reads
-- becomes misleading the first time a session is resumed.
--
-- endpoint_id: sessions are attributed per node, not per endpoint. A
-- device that fails over from direct UDP to the relay stays one session
-- on one node, so an endpoint column would record only which path it
-- happened to start on.
ALTER TABLE sessions
  DROP FOREIGN KEY fk_sessions_endpoint;
ALTER TABLE sessions
  DROP COLUMN endpoint_id,
  DROP COLUMN started_at;

-- verified_at is NOT dropped either.
--
-- It sits on attestation_records, not audit_log — and 0.18.0's
-- recordAttestation writes rows to that table, so the column is
-- populated by its DEFAULT on every registration. The baseline entry
-- described it as an audit-chain timestamp, which was simply wrong.
--
-- Two of the six turned out to be misreadings rather than dead columns.
-- Worth stating plainly: the wiring check finds candidates, it does not
-- make the decision.
