-- Whether the gateway's responder is listening on the tunnel address.
--
-- The tutorial's probe target is 10.78.0.1:8080. A gateway whose
-- responder is down (old image, crashed) looks identical from the
-- phone to one whose handshake never completed: 응답 없음 either way.
-- The agent can tell the two apart from inside the container; this
-- column carries that to the console.
ALTER TABLE nodes ADD COLUMN responder_up BOOLEAN NULL AFTER peer_count;
