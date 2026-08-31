-- Scope AI identity name uniqueness to active (non-deleted) rows only.

ALTER TABLE ai_identities DROP CONSTRAINT IF EXISTS ai_identities_name_key;

CREATE UNIQUE INDEX IF NOT EXISTS idx_ai_identities_name_active
    ON ai_identities (name)
    WHERE deleted_at IS NULL;
