ALTER TABLE network_members
    ADD COLUMN IF NOT EXISTS role TEXT NOT NULL DEFAULT 'MEMBER';

UPDATE network_members nm
SET role = 'OWNER'
FROM networks n
WHERE nm.network_id = n.id AND nm.user_id = n.owner_id;

CREATE TABLE IF NOT EXISTS session_tokens (
    access_token TEXT PRIMARY KEY,
    refresh_token TEXT NOT NULL UNIQUE,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at_unix BIGINT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_session_tokens_user_id ON session_tokens(user_id);
