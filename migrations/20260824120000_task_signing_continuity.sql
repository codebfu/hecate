-- Continuity signatures for task-signing key rotation.
ALTER TABLE agents
    ADD COLUMN IF NOT EXISTS task_signing_continuity_sig_b64 TEXT,
    ADD COLUMN IF NOT EXISTS task_signing_continuity_chain JSONB NOT NULL DEFAULT '[]'::jsonb;

INSERT INTO server_settings (key, value, updated_at)
VALUES ('key_rotation_interval_secs', '604800'::jsonb, now())
ON CONFLICT (key) DO NOTHING;

UPDATE server_settings
SET value = '604800'::jsonb, updated_at = now()
WHERE key = 'key_rotation_interval_secs' AND value = '0'::jsonb;
