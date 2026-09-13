-- AidotVpn MariaDB initialization
--
-- The mariadb image only creates one database via MARIADB_DATABASE/USER env
-- vars. We need a second database for Keycloak. This script runs once on
-- first container startup and creates that database plus a dedicated user.
--
-- Variables are interpolated by the official entrypoint at the time the
-- script runs; we use Docker's substitution syntax via the env-prefix.
--
-- Note: MariaDB does not support env-var interpolation inside SQL, so the
-- init script template here is hand-written for the env vars we use.
-- The real values are baked in by docker-entrypoint at boot time using the
-- (the Keycloak database and its init script were removed in 1.8.0)

-- We intentionally leave this file empty: the work is done by the .sh
-- companion file because the official entrypoint only supports SQL files
-- with literal values. Shell scripts get env vars; pure SQL does not.

SELECT 'AidotVpn MariaDB init' AS note;
