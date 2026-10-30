ALTER TABLE networks
    ALTER COLUMN file_transfer_max_bytes SET DEFAULT 67108864;

ALTER TABLE file_transfers
    ADD COLUMN IF NOT EXISTS payload_uploaded_bytes BIGINT NOT NULL DEFAULT 0;

UPDATE file_transfers
SET payload_uploaded_bytes = size_bytes
WHERE payload_ready = TRUE
  AND payload_uploaded_bytes = 0;
