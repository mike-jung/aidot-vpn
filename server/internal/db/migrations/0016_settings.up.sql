-- Tenant settings, keyed.
--
-- Created for the enrollment password, which 1.2.0 read from the
-- environment with this reasoning in a comment:
--
--   "putting it in a table invites a UI for editing it — at which point
--    it becomes a password that can be changed by anyone who reaches an
--    admin screen."
--
-- That argument does not hold. Anyone who reaches an admin screen can
-- already approve devices, which is strictly more than changing the
-- password that decides who may queue for approval. The threat it
-- describes is not one the environment variable was protecting against.
--
-- What the env-only version did cost was real: an operator who wanted to
-- rotate the password had to edit a file on the server and restart, and
-- one who simply wanted to read it — to tell a nurse — had to ssh in.
--
-- Values are stored in plaintext, deliberately. The enrollment password
-- has to be readable so it can be told to staff, the same way a router's
-- admin UI shows the wifi key. Hashing it would make the one thing it is
-- for impossible, and it protects nothing on its own: knowing it gets a
-- request into a queue an admin still has to approve.
CREATE TABLE settings (
  tenant_id  BINARY(16)   NOT NULL,
  name       VARCHAR(64)  NOT NULL,
  value      TEXT         NOT NULL,
  updated_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6)
                          ON UPDATE CURRENT_TIMESTAMP(6),
  updated_by BINARY(16)   NULL,

  PRIMARY KEY (tenant_id, name),
  CONSTRAINT fk_settings_tenant
    FOREIGN KEY (tenant_id) REFERENCES tenants (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
