-- The one-time registration grant handed to a device after approval.
--
-- Approval does not create the device. It issues a single-use enrollment
-- token and parks it here for the phone's next poll, so registration
-- stays on the path it already had — the alternative was returning a PSK
-- and a client certificate from an unauthenticated endpoint.
--
-- Cleared on read. A request id that leaks afterwards is then worth
-- nothing, and the token behind it is single-use with a five-minute
-- expiry regardless.
ALTER TABLE enrollment_requests
  ADD COLUMN grant_token VARCHAR(64) NULL AFTER device_id;
