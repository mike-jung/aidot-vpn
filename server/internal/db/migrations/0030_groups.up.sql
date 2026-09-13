-- Groups: a policy applied to many devices at once.
--
-- Until now a policy was attached to one device at a time. Changing what
-- thirty nurses can reach meant thirty edits, and an admin who missed
-- one left a phone on the old rules with nothing on screen to say so.
-- NetBird and Firezone both solve this by putting the policy on a group
-- and the devices in it; this is the same shape at the size this
-- product needs.
--
-- Resolution is an override, not a merge: a device's own policy_id wins
-- if set, otherwise it inherits the group's. Merging two policies would
-- mean deciding what "both allow 10.0.0.0/8 and deny it" means, and
-- there is no answer to that a hospital administrator should have to
-- reason about. One policy applies, and the screen says which.
CREATE TABLE device_groups (
  id          BINARY(16)   NOT NULL PRIMARY KEY,
  tenant_id   BINARY(16)   NOT NULL,
  name        VARCHAR(80)  NOT NULL,
  description VARCHAR(255) NULL,
  policy_id   BINARY(16)   NULL,
  created_at  TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  updated_at  TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
  deleted_at  TIMESTAMP(6) NULL,
  UNIQUE KEY uq_group_name (tenant_id, name),
  CONSTRAINT fk_group_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id),
  CONSTRAINT fk_group_policy FOREIGN KEY (policy_id) REFERENCES policies(id)
);

ALTER TABLE devices ADD COLUMN group_id BINARY(16) NULL AFTER policy_id;
ALTER TABLE devices ADD CONSTRAINT fk_device_group
  FOREIGN KEY (group_id) REFERENCES device_groups(id);
