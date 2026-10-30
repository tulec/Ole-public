ALTER TABLE audit_events
    ADD COLUMN IF NOT EXISTS network_id TEXT;

CREATE INDEX IF NOT EXISTS idx_audit_events_network_created_at
    ON audit_events(network_id, created_at_unix DESC);
