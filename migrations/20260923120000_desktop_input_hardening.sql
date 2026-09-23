-- Desktop input hardening (pentest §12/§13):
-- - desktop_policy JSON on capability profiles (allow_os_launchers opt-in)
-- - sliding keystroke buffer per (ai_identity, machine) for content-policy scan

ALTER TABLE capability_profiles
    ADD COLUMN IF NOT EXISTS desktop_policy JSONB NOT NULL DEFAULT '{}'::jsonb;

CREATE TABLE IF NOT EXISTS ai_desktop_input_buffers (
    ai_identity_id UUID NOT NULL REFERENCES ai_identities(id) ON DELETE CASCADE,
    machine_id UUID NOT NULL REFERENCES machines(id) ON DELETE CASCADE,
    buffer TEXT NOT NULL DEFAULT '',
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (ai_identity_id, machine_id)
);

CREATE INDEX IF NOT EXISTS idx_ai_desktop_input_buffers_updated_at
    ON ai_desktop_input_buffers (updated_at);
