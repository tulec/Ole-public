CREATE TABLE IF NOT EXISTS devices (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    public_key TEXT NOT NULL DEFAULT '',
    fingerprint TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL,
    created_at_unix BIGINT NOT NULL,
    revoked_at_unix BIGINT NOT NULL DEFAULT 0
);

ALTER TABLE peers
    ADD COLUMN IF NOT EXISTS device_id TEXT REFERENCES devices(id) ON DELETE RESTRICT;

CREATE INDEX IF NOT EXISTS idx_devices_user_id ON devices(user_id);
CREATE INDEX IF NOT EXISTS idx_peers_device_id ON peers(device_id);
