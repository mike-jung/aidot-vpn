-- Device-initiated enrollment with admin approval.
--
-- Replaces the flow where an admin created a token in the console and
-- the user somehow got 38 characters onto a phone. There is no channel
-- for that: not typeable, and emailing a bearer credential is worse than
-- the problem it solves.
--
-- Inverted, the direction works. The phone asks; the admin approves.
--
--   1. Operator enters the shared enrollment password on the phone.
--      Stops a stranger on the wifi from queuing requests. It is not the
--      security boundary — step 3 is.
--   2. Phone posts a request and shows a six-digit code.
--   3. Admin sees the same code beside the request and confirms it
--      matches the screen in front of them, then approves.
--
-- Step 3 is the actual authorisation, and the reason the shared password
-- being shared does not matter much: knowing it gets you into a queue an
-- admin still has to look at. The code binds a row in that queue to a
-- physical handset — the same argument as Bluetooth numeric comparison,
-- where the passkey is not secret and confirming it on both screens is
-- what defeats a man in the middle.
--
-- Six digits: readable aloud across a ward, and an attacker racing to
-- have their own request approved instead has to hit 1 in 10^6 within
-- the ten-minute window while the admin is looking at the real one.
CREATE TABLE enrollment_requests (
  id                 BINARY(16)   NOT NULL PRIMARY KEY,
  tenant_id          BINARY(16)   NOT NULL,

  -- What the device would have sent to /devices/register. Held until
  -- approval so the admin decides before anything is created.
  install_id         VARCHAR(128) NOT NULL,
  display_name       VARCHAR(128) NOT NULL,
  platform           VARCHAR(32)  NOT NULL DEFAULT 'android',
  device_public_key  VARCHAR(64)  NOT NULL,

  -- Shown on both screens. Not a secret: it is compared, not presented.
  verification_code  CHAR(6)      NOT NULL,

  -- pending | approved | rejected
  status             VARCHAR(16)  NOT NULL DEFAULT 'pending',

  -- Chosen by the admin at approval, so a device arrives governed.
  policy_id          BINARY(16)   NULL,

  -- Set once approved, so the phone's poll can be answered.
  device_id          BINARY(16)   NULL,

  expires_at         TIMESTAMP(6) NOT NULL,
  decided_at         TIMESTAMP(6) NULL,
  decided_by         BINARY(16)   NULL,
  created_at         TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),

  CONSTRAINT fk_enroll_req_tenant
    FOREIGN KEY (tenant_id) REFERENCES tenants (id) ON DELETE CASCADE,
  CONSTRAINT fk_enroll_req_policy
    FOREIGN KEY (policy_id) REFERENCES policies (id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE INDEX ix_enroll_req_tenant_status
  ON enrollment_requests (tenant_id, status, created_at);
