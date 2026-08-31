-- Dual-key rotation support for agent identity and task signing.

ALTER TABLE agents
    ADD COLUMN IF NOT EXISTS credential_pubkey_previous TEXT,
    ADD COLUMN IF NOT EXISTS credential_pubkey_previous_expires_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS task_signing_privkey_previous TEXT,
    ADD COLUMN IF NOT EXISTS task_signing_pubkey_previous_b64 TEXT,
    ADD COLUMN IF NOT EXISTS task_signing_previous_expires_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS credential_rotation_requested_at TIMESTAMPTZ;

-- Default overlap window: 7 days. Cron interval 0 = disabled.
INSERT INTO server_settings (key, value, updated_at)
VALUES
    ('key_rotation_overlap_secs', '604800'::jsonb, now()),
    ('key_rotation_interval_secs', '0'::jsonb, now())
ON CONFLICT (key) DO NOTHING;
