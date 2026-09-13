-- Failed logins per source address.
--
-- admins.failed_logins locks one account after five tries, which stops
-- someone guessing one password and does nothing about the shape an
-- attack actually takes: one address trying `admin@`, `it@`, `root@`
-- and a dozen others, five tries each, never tripping a single lock.
--
-- Counted per address rather than globally so one noisy client cannot
-- lock the console for everyone — which is the failure mode of a global
-- limiter and is itself a denial of service.
CREATE TABLE login_attempts (
  ip          VARCHAR(64)  NOT NULL PRIMARY KEY,
  failures    INT          NOT NULL DEFAULT 0,
  first_at    TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  locked_until TIMESTAMP(6) NULL
);
