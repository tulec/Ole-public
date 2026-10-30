CREATE TABLE IF NOT EXISTS auth_abuse_alerts (
    attempt_key TEXT PRIMARY KEY,
    attempt_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    failure_count INTEGER NOT NULL,
    denied_count INTEGER NOT NULL,
    total_alerts INTEGER NOT NULL,
    first_detected_at_unix BIGINT NOT NULL,
    last_detected_at_unix BIGINT NOT NULL,
    last_alerted_at_unix BIGINT NOT NULL,
    blocked_until_unix BIGINT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_auth_abuse_alerts_last_detected
    ON auth_abuse_alerts(last_detected_at_unix DESC);
