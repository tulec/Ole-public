ALTER TABLE peers
    ADD COLUMN IF NOT EXISTS reachability TEXT NOT NULL DEFAULT 'UNKNOWN',
    ADD COLUMN IF NOT EXISTS connection_state TEXT NOT NULL DEFAULT 'IDLE',
    ADD COLUMN IF NOT EXISTS last_signaled_at_unix BIGINT NOT NULL DEFAULT 0;

CREATE TABLE IF NOT EXISTS signal_candidates (
    id TEXT PRIMARY KEY,
    peer_id TEXT NOT NULL REFERENCES peers(id) ON DELETE CASCADE,
    network_id TEXT NOT NULL REFERENCES networks(id) ON DELETE CASCADE,
    type TEXT NOT NULL,
    protocol TEXT NOT NULL,
    address TEXT NOT NULL,
    preference INTEGER NOT NULL DEFAULT 0,
    reachable BOOLEAN NOT NULL DEFAULT TRUE,
    created_at_unix BIGINT NOT NULL,
    expires_at_unix BIGINT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_signal_candidates_peer_id ON signal_candidates(peer_id);
CREATE INDEX IF NOT EXISTS idx_signal_candidates_expires_at_unix ON signal_candidates(expires_at_unix);
