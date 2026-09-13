ALTER TABLE devices DROP FOREIGN KEY fk_device_group;
ALTER TABLE devices DROP COLUMN group_id;
DROP TABLE IF EXISTS device_groups;
