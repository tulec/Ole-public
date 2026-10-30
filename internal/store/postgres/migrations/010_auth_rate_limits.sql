CREATE TABLE IF NOT EXISTS auth_rate_limits (
    attempt_key TEXT PRIMARY KEY,
    failures INTEGER NOT NULL DEFAULT 0,
    blocked_until_unix BIGINT NOT NULL DEFAULT 0,
    updated_at_unix BIGINT NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_auth_rate_limits_updated_at_unix
    ON auth_rate_limits(updated_at_unix);

CREATE INDEX IF NOT EXISTS idx_auth_rate_limits_blocked_until_unix
    ON auth_rate_limits(blocked_until_unix);
