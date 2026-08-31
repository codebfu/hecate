-- Security hardening: per-agent task signing key + rename command result columns

ALTER TABLE agents
    ADD COLUMN IF NOT EXISTS task_signing_privkey TEXT NOT NULL DEFAULT '';

ALTER TABLE command_results RENAME COLUMN stdout_enc TO stdout;
ALTER TABLE command_results RENAME COLUMN stderr_enc TO stderr;
