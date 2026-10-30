CREATE TABLE IF NOT EXISTS messages (
    id TEXT PRIMARY KEY,
    network_id TEXT NOT NULL REFERENCES networks(id) ON DELETE CASCADE,
    from_peer_id TEXT NOT NULL REFERENCES peers(id) ON DELETE CASCADE,
    text TEXT NOT NULL,
    sent_at_unix BIGINT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_messages_network_sent_at
    ON messages(network_id, sent_at_unix DESC, id DESC);

CREATE TABLE IF NOT EXISTS file_transfers (
    id TEXT PRIMARY KEY,
    network_id TEXT NOT NULL REFERENCES networks(id) ON DELETE CASCADE,
    from_peer_id TEXT NOT NULL REFERENCES peers(id) ON DELETE CASCADE,
    to_peer_id TEXT NOT NULL REFERENCES peers(id) ON DELETE CASCADE,
    file_name TEXT NOT NULL,
    size_bytes BIGINT NOT NULL,
    status TEXT NOT NULL,
    progress_percent INTEGER NOT NULL DEFAULT 0,
    cancel_reason TEXT
);

CREATE INDEX IF NOT EXISTS idx_file_transfers_network_status
    ON file_transfers(network_id, status, id DESC);
