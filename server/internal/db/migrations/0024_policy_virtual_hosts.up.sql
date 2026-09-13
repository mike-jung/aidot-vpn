-- A destination the phone knows by a made-up address.
--
-- A policy line of 192.168.0.22/32 sends that address to the phone, and
-- the phone routes to it by name: the real address is in the phone's
-- routing table, not the app's source, but it is on the handset all the
-- same. This table lets the phone be handed 10.79.0.22 instead, with the
-- gateway rewriting it to 192.168.0.22 on the way through. The phone
-- never learns the real one.
--
-- The virtual range is 10.79.0.0/16, chosen because 10.78.0.0/16 is
-- the device pool and a virtual destination inside it would collide
-- with a handset — at the 22nd enrolment for 10.79.0.22's obvious
-- sibling. Different second octet, no overlap, ever.
--
-- One virtual address maps to one real address. Ranges are not mapped:
-- a /24 → /24 rewrite needs arithmetic on every packet and there is no
-- case here that a handful of single hosts does not cover.
CREATE TABLE policy_virtual_hosts (
  id          BINARY(16)   NOT NULL PRIMARY KEY,
  policy_id   BINARY(16)   NOT NULL,
  virtual_ip  VARCHAR(45)  NOT NULL,   -- what the phone is told, in 10.79.0.0/16
  real_ip     VARCHAR(45)  NOT NULL,   -- what the gateway rewrites it to
  description VARCHAR(200) NULL,
  created_at  TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  UNIQUE KEY uq_virtual_per_policy (policy_id, virtual_ip),
  CONSTRAINT fk_vh_policy FOREIGN KEY (policy_id) REFERENCES policies(id) ON DELETE CASCADE
);
