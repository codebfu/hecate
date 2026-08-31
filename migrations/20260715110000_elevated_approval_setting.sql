ALTER TABLE ai_identities
    ADD COLUMN requires_approval_for_elevated BOOLEAN NOT NULL DEFAULT true;
