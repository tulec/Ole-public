ALTER TABLE file_transfers
    ADD COLUMN IF NOT EXISTS from_user_id TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS to_user_id TEXT NOT NULL DEFAULT '';

UPDATE file_transfers ft
SET
    from_user_id = COALESCE(NULLIF(from_user_id, ''), (SELECT p.user_id FROM peers p WHERE p.id = ft.from_peer_id), ''),
    to_user_id = COALESCE(NULLIF(to_user_id, ''), (SELECT p.user_id FROM peers p WHERE p.id = ft.to_peer_id), '');
