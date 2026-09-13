-- =============================================================================
-- Migration 0007 — add `wss_relay` endpoint mode
--
-- Phase 9 introduced cmd/relay (WebSocket-over-TLS bridge for clients
-- behind CGNAT / mobile carrier NAT). The Android client picks its
-- transport based on `node_endpoints.mode`:
--
--   wg          - direct UDP to public_host:public_port (Scenarios A/B)
--   wss_relay   - WebSocket to public_host:public_port using the bearer
--                 token issued by /devices/{id}/relay-token  (Scenario C)
--
-- The other existing modes (wg_junk, amneziawg, shadowsocks_*) are
-- reserved for future obfuscation work and unaffected.
--
-- Forward compatibility: mode-specific bits go in `params_json`. For
-- wss_relay the params are:
--
--   {"path": "/ws/mobile"}     // optional, defaults to /ws/mobile
--
-- This lets a single relay host under different paths (multi-tenant
-- relay deployments) without schema churn.
-- =============================================================================

ALTER TABLE node_endpoints
    MODIFY COLUMN mode ENUM(
        'wg',
        'wg_junk',
        'amneziawg',
        'shadowsocks_tcp',
        'shadowsocks_ws',
        'wss_relay'
    ) NOT NULL;
