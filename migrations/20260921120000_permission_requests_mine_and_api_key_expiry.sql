-- Copyright (C) 2026 Gaultier HUBERT
-- SPDX-License-Identifier: GPL-3.0-or-later

-- Bootstrap platform command: AI identities can list their own permission requests.
INSERT INTO command_definitions (name, description, risk_level)
VALUES (
    'permissions.requests.mine',
    'List permission requests owned by the calling AI identity',
    'low'
)
ON CONFLICT (name) DO UPDATE SET
    description = EXCLUDED.description,
    risk_level = EXCLUDED.risk_level;

UPDATE capability_profiles
SET allowed_commands = ARRAY[
        'system.info',
        'permissions.request',
        'permissions.requests.mine'
    ]::TEXT[],
    updated_at = now()
WHERE id = '00000000-0000-4000-8000-000000000002';

-- Optional API key expiration (NULL = never expires; existing rows stay never-expire).
ALTER TABLE ai_api_keys
    ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ;
