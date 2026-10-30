ALTER TABLE networks
    ADD COLUMN IF NOT EXISTS device_approval_required BOOLEAN NOT NULL DEFAULT FALSE;

CREATE TABLE IF NOT EXISTS network_device_approvals (
    network_id TEXT NOT NULL REFERENCES networks(id) ON DELETE CASCADE,
    device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    PRIMARY KEY (network_id, device_id)
);

CREATE INDEX IF NOT EXISTS idx_network_device_approvals_device_id ON network_device_approvals(device_id);
