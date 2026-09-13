-- Reverse 0005 — revert the dev-node public key back to the
-- placeholder zero value seeded by 0004 (pre-correction state).
--
-- Only revert if the row still has the corrected key, so a partial
-- rollback against an already-rolled-back DB is a no-op.

UPDATE nodes
   SET public_key = UNHEX('0000000000000000000000000000000000000000000000000000000000000000')
 WHERE id = UNHEX('019650000000700080000000000000B1')
   AND public_key = UNHEX('F0F5FBC5317DCA5FD87EB4F767BB271D24807D11175545A5C310EA237C875A46');
