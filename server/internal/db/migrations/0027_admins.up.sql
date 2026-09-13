-- Console administrators, and their sessions. Replaces Keycloak.
--
-- Keycloak served one purpose here — console login for a few admins per
-- hospital — and cost a JVM container, a realm file, a theme, a sync
-- script, and six defects in one week that were all about matching its
-- rules rather than ours. See docs/auth-design-ko.md.
--
-- Passwords are argon2id (PHC string, parameters embedded). Sessions are
-- server-side rows keyed by the SHA-256 of a random cookie value; the
-- cookie itself is never stored. Logout deletes the row: immediate and
-- certain, which a JWT never is.
CREATE TABLE admins (
  id            BINARY(16)    NOT NULL PRIMARY KEY,
  tenant_id     BINARY(16)    NOT NULL,
  email         VARCHAR(255)  NOT NULL,
  display_name  VARCHAR(100)  NOT NULL DEFAULT '',
  password_hash VARBINARY(255) NOT NULL,
  role          ENUM('admin','viewer') NOT NULL DEFAULT 'admin',
  must_change   BOOLEAN       NOT NULL DEFAULT TRUE,
  failed_logins INT           NOT NULL DEFAULT 0,
  locked_until  TIMESTAMP(6)  NULL,
  disabled_at   TIMESTAMP(6)  NULL,
  created_at    TIMESTAMP(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  updated_at    TIMESTAMP(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
  UNIQUE KEY uq_admin_email (tenant_id, email),
  CONSTRAINT fk_admin_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id)
);

CREATE TABLE admin_sessions (
  id           BINARY(16)   NOT NULL PRIMARY KEY,
  admin_id     BINARY(16)   NOT NULL,
  token_hash   BINARY(32)   NOT NULL,
  created_at   TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  last_used_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  expires_at   TIMESTAMP(6) NOT NULL,
  user_agent   VARCHAR(255) NOT NULL DEFAULT '',
  ip           VARCHAR(45)  NOT NULL DEFAULT '',
  UNIQUE KEY uq_session_token (token_hash),
  KEY ix_session_admin (admin_id),
  CONSTRAINT fk_session_admin FOREIGN KEY (admin_id) REFERENCES admins(id) ON DELETE CASCADE
);
