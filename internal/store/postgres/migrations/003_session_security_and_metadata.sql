ALTER TABLE session_tokens
    ADD COLUMN IF NOT EXISTS id TEXT,
    ADD COLUMN IF NOT EXISTS family_id TEXT,
    ADD COLUMN IF NOT EXISTS device_name TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS ip TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS user_agent TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS last_used_at_unix BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS replaced_by_token TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS revoked_at_unix BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS reuse_detected_at_unix BIGINT NOT NULL DEFAULT 0;

UPDATE session_tokens
SET id = COALESCE(NULLIF(id, ''), access_token),
    family_id = COALESCE(NULLIF(family_id, ''), access_token),
    last_used_at_unix = CASE WHEN last_used_at_unix = 0 THEN expires_at_unix ELSE last_used_at_unix END
WHERE id IS NULL OR id = '' OR family_id IS NULL OR family_id = '' OR last_used_at_unix = 0;

ALTER TABLE session_tokens
    ALTER COLUMN id SET NOT NULL,
    ALTER COLUMN family_id SET NOT NULL;

CREATE INDEX IF NOT EXISTS idx_session_tokens_family_id ON session_tokens(family_id);
CREATE INDEX IF NOT EXISTS idx_session_tokens_last_used_at ON session_tokens(last_used_at_unix DESC);
