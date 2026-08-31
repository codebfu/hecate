-- Propylaea edge proxies: enrollment, credentials, and sync support.

CREATE TYPE proxy_state AS ENUM ('pending_approval', 'active', 'revoked');

CREATE TABLE proxies (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    hostname TEXT NOT NULL,
    credential_pubkey TEXT NOT NULL,
    credential_pubkey_previous TEXT,
    credential_pubkey_previous_expires_at TIMESTAMPTZ,
    state proxy_state NOT NULL DEFAULT 'pending_approval',
    version TEXT,
    enrolled_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at TIMESTAMPTZ,
    last_seen_at TIMESTAMPTZ,
    attestation_json JSONB NOT NULL DEFAULT '{}'
);

CREATE TABLE proxy_enrollment_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    token_hmac TEXT NOT NULL UNIQUE,
    expires_at TIMESTAMPTZ NOT NULL,
    used_at TIMESTAMPTZ,
    bound_tags TEXT[] NOT NULL DEFAULT '{}'
);

CREATE TABLE proxy_nonce_cache (
    proxy_id UUID NOT NULL,
    nonce TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (proxy_id, nonce)
);

CREATE INDEX proxy_nonce_cache_expires_at_idx ON proxy_nonce_cache (expires_at);

INSERT INTO server_settings (key, value, updated_at)
VALUES ('proxy_enrollment_auto_approve', 'false'::jsonb, now())
ON CONFLICT (key) DO NOTHING;
