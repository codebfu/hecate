CREATE TABLE command_artifacts (
    id UUID PRIMARY KEY,
    command_id UUID REFERENCES command_queue(id) ON DELETE CASCADE,
    ai_identity_id UUID NOT NULL REFERENCES ai_identities(id) ON DELETE CASCADE,
    direction TEXT NOT NULL CHECK (direction IN ('input', 'output')),
    storage_path TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    size_bytes BIGINT NOT NULL,
    original_name TEXT NOT NULL DEFAULT '',
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX command_artifacts_command_id_idx ON command_artifacts (command_id);
CREATE INDEX command_artifacts_expires_at_idx ON command_artifacts (expires_at);
CREATE INDEX command_artifacts_ai_identity_id_idx ON command_artifacts (ai_identity_id);

INSERT INTO command_definitions (name, description, risk_level) VALUES
    ('file.pull', 'Read a file on the machine and stage it for AI download', 'high'),
    ('file.push', 'Write a staged file to a path on the machine', 'high'),
    ('remote.download', 'Download a URL from the machine network', 'high');
