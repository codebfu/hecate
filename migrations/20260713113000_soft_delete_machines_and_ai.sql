-- Add soft-delete support for machines and AI identities.

ALTER TABLE machines
    ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS idx_machines_deleted_at ON machines (deleted_at);

ALTER TABLE ai_identities
    ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS idx_ai_identities_deleted_at ON ai_identities (deleted_at);

