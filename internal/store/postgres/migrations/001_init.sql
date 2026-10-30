CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    status TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS networks (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    owner_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    access TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS network_members (
    network_id TEXT NOT NULL REFERENCES networks(id) ON DELETE CASCADE,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    PRIMARY KEY (network_id, user_id)
);

CREATE TABLE IF NOT EXISTS virtual_ip_pools (
    network_id TEXT PRIMARY KEY REFERENCES networks(id) ON DELETE CASCADE,
    cidr TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS virtual_ip_leases (
    network_id TEXT NOT NULL REFERENCES networks(id) ON DELETE CASCADE,
    ip TEXT NOT NULL,
    peer_id TEXT NOT NULL,
    PRIMARY KEY (network_id, ip),
    UNIQUE (network_id, peer_id)
);

CREATE TABLE IF NOT EXISTS invites (
    code TEXT PRIMARY KEY,
    network_id TEXT NOT NULL REFERENCES networks(id) ON DELETE CASCADE,
    expires_at_unix BIGINT NOT NULL,
    max_uses INTEGER NOT NULL,
    uses INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS peers (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    network_id TEXT NOT NULL REFERENCES networks(id) ON DELETE CASCADE,
    virtual_ip TEXT NOT NULL,
    endpoint TEXT NOT NULL,
    status TEXT NOT NULL,
    last_seen_unix BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS tunnels (
    id TEXT PRIMARY KEY,
    network_id TEXT NOT NULL REFERENCES networks(id) ON DELETE CASCADE,
    peer_a TEXT NOT NULL REFERENCES peers(id) ON DELETE CASCADE,
    peer_b TEXT NOT NULL REFERENCES peers(id) ON DELETE CASCADE,
    mode TEXT NOT NULL,
    state TEXT NOT NULL,
    created_at_unix BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_events (
    id TEXT PRIMARY KEY,
    actor_user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    type TEXT NOT NULL,
    details TEXT NOT NULL,
    created_at_unix BIGINT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_peers_network_id ON peers(network_id);
CREATE INDEX IF NOT EXISTS idx_tunnels_network_id ON tunnels(network_id);
CREATE INDEX IF NOT EXISTS idx_audit_events_created_at ON audit_events(created_at_unix DESC);
