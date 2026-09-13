CREATE TABLE device_state_tokens (
  device_id BINARY(16) NOT NULL PRIMARY KEY,
  token_hash BINARY(32) NOT NULL,
  created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  CONSTRAINT fk_state_token_device FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE
);
