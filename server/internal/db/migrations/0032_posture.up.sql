-- Device posture: refuse a handset whose OS is too old.
--
-- An Android that stopped getting security patches is a way into the
-- hospital network that the VPN cannot see past — it will carry
-- whatever is on that phone straight through the tunnel. NetBird calls
-- this a posture check and it is their central Zero Trust feature;
-- Defguard has it planned for 2.1. The controller already receives the
-- OS version, so the only thing missing was a rule and somewhere to
-- enforce it.
--
-- A numeric column rather than parsing os_version, which is a display
-- string ("Android 16 (sdk 36)") and the wrong thing to write a query
-- against: a phrasing change in the app would silently disable the
-- check.
ALTER TABLE devices ADD COLUMN os_sdk INT NULL AFTER os_version;

-- 0 disables the check, which is the default: turning this on without
-- an admin choosing to would lock out whatever is already deployed.
ALTER TABLE tenants ADD COLUMN min_os_sdk INT NOT NULL DEFAULT 0;
