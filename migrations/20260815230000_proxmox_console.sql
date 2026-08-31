-- Proxmox console commands, session tracking, and helper releases.

INSERT INTO command_definitions (name, description, risk_level) VALUES
    ('proxmox.info', 'Probe Proxmox console helper capability and host information', 'low'),
    ('proxmox.vm.list', 'List Proxmox virtual machines available for console access', 'low'),
    ('proxmox.console.open', 'Open a persistent Proxmox virtual machine console session', 'high'),
    ('proxmox.console.frame', 'Fetch the latest frame from a Proxmox console session', 'high'),
    ('proxmox.console.input', 'Send input events to a Proxmox console session', 'high'),
    ('proxmox.console.close', 'Close a Proxmox console session', 'high');

CREATE TABLE IF NOT EXISTS proxmox_console_sessions (
    id UUID PRIMARY KEY,
    machine_id UUID NOT NULL REFERENCES machines(id),
    ai_identity_id UUID NOT NULL REFERENCES ai_identities(id),
    status TEXT NOT NULL DEFAULT 'open'
        CHECK (status IN ('open', 'closed', 'expired')),
    vmid INT NOT NULL,
    fps INT NOT NULL DEFAULT 2,
    format TEXT NOT NULL DEFAULT 'png',
    max_duration_secs INT NOT NULL DEFAULT 600,
    opened_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL,
    closed_at TIMESTAMPTZ,
    helper_session_id TEXT
);

CREATE INDEX IF NOT EXISTS idx_proxmox_console_sessions_machine_open
    ON proxmox_console_sessions (machine_id, status)
    WHERE status = 'open';

CREATE INDEX IF NOT EXISTS idx_proxmox_console_sessions_identity
    ON proxmox_console_sessions (ai_identity_id, status);

ALTER TABLE agent_releases
    DROP CONSTRAINT agent_releases_component_check;

ALTER TABLE agent_releases
    ADD CONSTRAINT agent_releases_component_check
    CHECK (component IN ('agent', 'desktop', 'proxmox'));

ALTER TABLE machines
    ADD COLUMN IF NOT EXISTS proxmox_version TEXT;
