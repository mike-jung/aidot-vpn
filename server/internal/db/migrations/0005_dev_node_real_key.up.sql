-- =============================================================================
-- Migration 0005 — replace dev-node placeholder pubkey with a real X25519 key
--
-- 0004 seeded the dev node with 32 zero bytes, which wireguard-go (and
-- every other WireGuard implementation) rejects with "invalid public
-- key" because it's the X25519 identity element. The handshake never
-- starts, so the Android client's tunnel comes UP at the OS level but
-- can't actually transmit.
--
-- This migration overwrites that key with a well-formed value, derived
-- deterministically from a dev seed so:
--
--   * Re-running migrations on a fresh DB lands on the same value.
--   * A developer who wants to run the matching data-plane daemon can
--     reproduce the private key by repeating the same derivation
--     (sha256("aidotvpn-dev-node-1-2026") + X25519 clamping).
--
-- Production deployments register their nodes via NodeService at
-- runtime; this row is overwritten then and the placeholder key never
-- ships into prod.
-- =============================================================================

-- NOTE on the value below: an earlier draft of this file had the wrong
-- public key (a hash-collision-style typo from a stale derivation
-- attempt). Migration 0006 corrects DBs that already applied the wrong
-- value. New deploys land on the right value here directly.
--
-- Pairing with infra/wireguard/wg0.conf:
--   PrivateKey  ON18RsAf+Roxjy3WVo3vdg6mGUCacC+3id3csLYDfkA=  (base64)
--   PublicKey   8PX7xTF9yl/YfrT3Z7snHSSAfREXVUWlwxDqI3yHWkY=  (base64)
--   hex         F0F5FBC5317DCA5FD87EB4F767BB271D24807D11175545A5C310EA237C875A46

UPDATE nodes
   SET public_key = UNHEX('F0F5FBC5317DCA5FD87EB4F767BB271D24807D11175545A5C310EA237C875A46')
 WHERE id = UNHEX('019650000000700080000000000000B1')
   AND public_key = UNHEX('0000000000000000000000000000000000000000000000000000000000000000');
