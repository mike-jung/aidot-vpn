-- Whether this device is currently reaching the gateway through the
-- relay.
--
-- A handset on a network that blocks UDP — hotel wifi, some carriers —
-- connects over WebSocket-TLS instead. It works, and it is slower, and
-- nothing in the console showed which devices were doing it. "Why is
-- only this phone slow" had no answer.
ALTER TABLE devices
  ADD COLUMN via_relay BOOLEAN NULL AFTER tx_bytes;
