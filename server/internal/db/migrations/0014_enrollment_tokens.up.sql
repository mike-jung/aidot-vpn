-- Enrollment tokens.
--
-- Until now the only way to enrol a phone was to mint an OIDC access
-- token with curl and paste it into the app. That works and is a poor
-- thing to put in a tutorial: it needs a terminal, the realm's client
-- id, and a user's password — none of which an operator enrolling a
-- nurse's handset should have to touch.
--
-- The shape here follows what Android Management API, Elastic Fleet and
-- Chrome Enterprise converged on:
--
--   * bound to a policy, so a device arrives already governed rather
--     than in a "registered but reaches nothing" limbo
--   * an expiry, because an enrolment credential that lives forever is
--     a credential someone will find in a chat log next year
--   * single-use or multi-use, chosen at creation — a per-device token
--     is the safer default and a shared one is what you want for a
--     cart of twenty tablets
--   * revocable independently of the devices it enrolled, so pausing
--     enrolment does not disconnect anyone
--
-- Only the SHA-256 is stored, matching nodes.agent_token_hash. The
-- plaintext is shown once at creation and is unrecoverable after that.
-- A token that can be re-read from the database is one that leaks with
-- the database.
CREATE TABLE enrollment_tokens (
  id             BINARY(16)   NOT NULL PRIMARY KEY,
  tenant_id      BINARY(16)   NOT NULL,

  -- Human label, so a list of hashes is navigable.
  name           VARCHAR(128) NOT NULL,

  token_hash     BINARY(32)   NOT NULL,

  -- Policy applied to devices enrolled with this token. NULL is
  -- permitted but means the device lands unbound and reaches nothing,
  -- so the console warns when it is left empty.
  policy_id      BINARY(16)   NULL,

  -- 0 = unlimited. Otherwise enrolment fails once used_count reaches it.
  max_uses       INT          NOT NULL DEFAULT 1,
  used_count     INT          NOT NULL DEFAULT 0,

  expires_at     TIMESTAMP(6) NOT NULL,
  revoked_at     TIMESTAMP(6) NULL,

  created_by     BINARY(16)   NULL,
  created_at     TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),

  CONSTRAINT fk_enroll_tokens_tenant
    FOREIGN KEY (tenant_id) REFERENCES tenants (id) ON DELETE CASCADE,
  CONSTRAINT fk_enroll_tokens_policy
    FOREIGN KEY (policy_id) REFERENCES policies (id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Lookup at enrolment time is by hash.
CREATE UNIQUE INDEX ux_enrollment_tokens_hash ON enrollment_tokens (token_hash);
CREATE INDEX ix_enrollment_tokens_tenant ON enrollment_tokens (tenant_id, created_at);
