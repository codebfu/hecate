-- Authz tag source toggles (safe defaults: auto+operator on, agent_custom off).
INSERT INTO server_settings (key, value) VALUES
    ('authz_tags_include_auto', 'true'),
    ('authz_tags_include_operator', 'true'),
    ('authz_tags_include_agent_custom', 'false'),
    ('content_policy_lockout_seconds', '3600')
ON CONFLICT (key) DO NOTHING;

-- Per-AI content-policy strike / lockout state.
CREATE TABLE IF NOT EXISTS ai_content_policy_state (
    ai_identity_id UUID PRIMARY KEY REFERENCES ai_identities(id) ON DELETE CASCADE,
    violation_count INT NOT NULL DEFAULT 0,
    locked_until TIMESTAMPTZ,
    last_violation_at TIMESTAMPTZ,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
