-- Reverse 0007 — drop wss_relay from the enum. Aborts if any rows
-- still reference it (operator must remove or migrate them first).

UPDATE node_endpoints SET enabled = FALSE WHERE mode = 'wss_relay';

ALTER TABLE node_endpoints
    MODIFY COLUMN mode ENUM(
        'wg',
        'wg_junk',
        'amneziawg',
        'shadowsocks_tcp',
        'shadowsocks_ws'
    ) NOT NULL;
