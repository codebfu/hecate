-- Hecate v1 initial schema

CREATE TYPE operator_role AS ENUM ('admin', 'operator');
CREATE TYPE auth_stage AS ENUM ('password', 'full');
CREATE TYPE agent_state AS ENUM ('pending_approval', 'active', 'revoked');
CREATE TYPE command_status AS ENUM (
    'pending_approval', 'queued', 'dispatched', 'running',
    'completed', 'failed', 'expired', 'cancelled'
);

CREATE TABLE operators (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    login VARCHAR(32) NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role operator_role NOT NULL DEFAULT 'operator',
    created_by_id UUID REFERENCES operators(id),
    must_change_password BOOLEAN NOT NULL DEFAULT false,
    onboarding_complete BOOLEAN NOT NULL DEFAULT false,
    disabled_at TIMESTAMPTZ,
    failed_login_count INT NOT NULL DEFAULT 0,
    locked_until TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_login_at TIMESTAMPTZ
);

CREATE TABLE operator_webauthn_credentials (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    operator_id UUID NOT NULL REFERENCES operators(id) ON DELETE CASCADE,
    name VARCHAR(128) NOT NULL,
    credential_id BYTEA NOT NULL UNIQUE,
    public_key BYTEA NOT NULL,
    sign_count BIGINT NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ
);

CREATE TABLE operator_sessions (
    session_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    operator_id UUID NOT NULL REFERENCES operators(id) ON DELETE CASCADE,
    expires_at TIMESTAMPTZ NOT NULL,
    csrf_token_hash TEXT NOT NULL,
    auth_stage auth_stage NOT NULL DEFAULT 'password'
);

CREATE TABLE machines (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    hostname TEXT NOT NULL,
    os TEXT NOT NULL,
    arch TEXT NOT NULL,
    tags TEXT[] NOT NULL DEFAULT '{}',
    status TEXT NOT NULL DEFAULT 'offline',
    agent_version TEXT,
    last_seen_at TIMESTAMPTZ,
    attestation_json JSONB NOT NULL DEFAULT '{}'
);

CREATE TABLE agents (
    machine_id UUID PRIMARY KEY REFERENCES machines(id) ON DELETE CASCADE,
    credential_pubkey TEXT NOT NULL,
    state agent_state NOT NULL DEFAULT 'pending_approval',
    enrolled_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at TIMESTAMPTZ,
    last_nonce_window TIMESTAMPTZ
);

CREATE TABLE enrollment_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    token_hmac TEXT NOT NULL UNIQUE,
    expires_at TIMESTAMPTZ NOT NULL,
    used_at TIMESTAMPTZ,
    bound_tags TEXT[] NOT NULL DEFAULT '{}'
);

CREATE TABLE ai_identities (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL DEFAULT '',
    active BOOLEAN NOT NULL DEFAULT true,
    requires_approval_for_shell BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE ai_api_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    ai_identity_id UUID NOT NULL REFERENCES ai_identities(id) ON DELETE CASCADE,
    key_hmac TEXT NOT NULL UNIQUE,
    prefix TEXT NOT NULL,
    revoked_at TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE ai_permissions (
    ai_identity_id UUID PRIMARY KEY REFERENCES ai_identities(id) ON DELETE CASCADE,
    rules JSONB NOT NULL DEFAULT '{}'
);

CREATE TABLE command_definitions (
    name TEXT PRIMARY KEY,
    description TEXT NOT NULL DEFAULT '',
    input_schema JSONB NOT NULL DEFAULT '{}',
    risk_level TEXT NOT NULL DEFAULT 'low'
);

CREATE TABLE command_queue (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    machine_id UUID NOT NULL REFERENCES machines(id),
    ai_identity_id UUID REFERENCES ai_identities(id),
    command_name TEXT NOT NULL,
    params JSONB NOT NULL DEFAULT '{}',
    status command_status NOT NULL DEFAULT 'queued',
    timeout_secs INT NOT NULL DEFAULT 30,
    dispatched_at TIMESTAMPTZ,
    dispatched_agent_id UUID REFERENCES machines(id),
    started_at TIMESTAMPTZ,
    finished_at TIMESTAMPTZ,
    cancel_requested_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE command_results (
    command_id UUID PRIMARY KEY REFERENCES command_queue(id) ON DELETE CASCADE,
    stdout_enc TEXT NOT NULL DEFAULT '',
    stderr_enc TEXT NOT NULL DEFAULT '',
    exit_code INT,
    truncated BOOLEAN NOT NULL DEFAULT false,
    byte_count INT NOT NULL DEFAULT 0
);

CREATE TABLE audit_events (
    id BIGSERIAL PRIMARY KEY,
    prev_hash TEXT NOT NULL DEFAULT '',
    entry_hash TEXT NOT NULL,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    target TEXT NOT NULL DEFAULT '',
    ip TEXT NOT NULL DEFAULT '',
    payload_hash TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE agent_releases (
    version TEXT NOT NULL,
    os TEXT NOT NULL,
    arch TEXT NOT NULL,
    artifact_path TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    signature TEXT NOT NULL,
    published_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at TIMESTAMPTZ,
    PRIMARY KEY (version, os, arch)
);

CREATE TABLE server_settings (
    key TEXT PRIMARY KEY,
    value JSONB NOT NULL DEFAULT '{}',
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE agent_nonce_cache (
    agent_id UUID NOT NULL REFERENCES machines(id) ON DELETE CASCADE,
    nonce TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (agent_id, nonce)
);

INSERT INTO command_definitions (name, description, risk_level) VALUES
    ('system.info', 'Read-only system information', 'low'),
    ('shell.run', 'Execute explicit argv via execve', 'high');

INSERT INTO server_settings (key, value) VALUES
    ('audit_retention_days', '90');
