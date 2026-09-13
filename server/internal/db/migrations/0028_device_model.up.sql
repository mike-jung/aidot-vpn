-- The handset model, as the phone reports it.
--
-- "서버에 보이는 단말 정보가 너무 없어서" — and the app was already
-- sending this; the controller dropped it on the floor. MAC addresses
-- are not an option: Android 10 and later return 02:00:00:00:00:00 to
-- apps and randomise the real address per network, so it identifies
-- nothing and changes when the nurse walks to another floor. The model
-- string does what an admin actually needs from that column — telling
-- one 검증 폰 from another in a list of thirty.
ALTER TABLE devices ADD COLUMN model VARCHAR(80) NULL AFTER platform;
