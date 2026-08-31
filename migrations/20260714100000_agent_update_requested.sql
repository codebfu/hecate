ALTER TABLE machines ADD COLUMN IF NOT EXISTS agent_update_requested_at TIMESTAMPTZ;
