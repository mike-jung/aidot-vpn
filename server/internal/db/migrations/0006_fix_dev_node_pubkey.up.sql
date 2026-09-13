-- =============================================================================
-- Migration 0006 — correct the dev-node public key
--
-- 0005 stamped a public key value into nodes.public_key that did NOT
-- match what wg0.conf's PrivateKey actually derives to. The mismatch
-- meant every Android handshake encrypted to a curve point the wg
-- container had no private key for, so handshakes silently failed.
--
-- Correct pairing:
--   PrivateKey (in wg0.conf):
--     base64 ON18RsAf+Roxjy3WVo3vdg6mGUCacC+3id3csLYDfkA=
--   PublicKey (this migration sets in DB):
--     base64 8PX7xTF9yl/YfrT3Z7snHSSAfREXVUWlwxDqI3yHWkY=
--     hex    F0F5FBC5317DCA5FD87EB4F767BB271D24807D11175545A5C310EA237C875A46
--
-- We only update the row if it still has the wrong value, so re-running
-- this on a fresh DB (where 0005 has been corrected — see below) is a
-- no-op.
-- =============================================================================

UPDATE nodes
   SET public_key = UNHEX('F0F5FBC5317DCA5FD87EB4F767BB271D24807D11175545A5C310EA237C875A46')
 WHERE id = UNHEX('019650000000700080000000000000B1')
   AND public_key = UNHEX('361F5230A6A37FE4CCBAD168491F7E5CAFC1A77E1849FA427CC22705AEE86C60');
