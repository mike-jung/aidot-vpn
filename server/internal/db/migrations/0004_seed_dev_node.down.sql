-- Reverse 0004 — remove the seeded dev node and endpoint. Real nodes
-- (registered via NodeService at runtime) are unaffected: this only
-- targets the IDs we inserted in 0004's up migration.

DELETE FROM node_endpoints
 WHERE id = UNHEX('019650000000700080000000000000B2');

DELETE FROM nodes
 WHERE id = UNHEX('019650000000700080000000000000B1');
