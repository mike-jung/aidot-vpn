-- Reverse of 0012_dns.up.sql.
--
-- Destructive in a way worth stating: dropping policy_hostnames removes
-- every hostname-based rule, and the resolved addresses go with them. A
-- policy that relied entirely on hostnames becomes a policy with no
-- destinations — which, under the deny-by-default behaviour introduced in
-- 0.10.0, means the attached devices reach nothing.
--
-- Export the hostname list before rolling back if those rules matter.

DROP TABLE IF EXISTS policy_hostname_resolutions;
DROP TABLE IF EXISTS policy_hostnames;

ALTER TABLE policies
  DROP COLUMN dns_search_domains,
  DROP COLUMN dns_servers;
