-- When this admin last signed in, and from where.
--
-- Shown on the next login. An account used at 3am from an address its
-- owner does not recognise is something only the owner can judge, and
-- they can only judge it if they are told — which is why every console
-- that handles anything sensitive shows it.
ALTER TABLE admins ADD COLUMN last_login_at TIMESTAMP(6) NULL;
ALTER TABLE admins ADD COLUMN last_login_ip VARCHAR(64) NULL;
