-- Desktop / computer-use commands and session tracking.

INSERT INTO command_definitions (name, description, risk_level) VALUES
    ('desktop.info', 'Probe desktop helper capability, monitors, and session state', 'low'),
    ('desktop.screenshot', 'Capture a display or region as a PNG artifact', 'high'),
    ('desktop.move', 'Move the mouse cursor', 'high'),
    ('desktop.click', 'Click the mouse', 'high'),
    ('desktop.scroll', 'Scroll the mouse wheel', 'high'),
    ('desktop.drag', 'Drag the mouse from one point to another', 'high'),
    ('desktop.type', 'Type Unicode text', 'high'),
    ('desktop.key', 'Press, release, or tap a key combo', 'high'),
    ('desktop.clipboard.get', 'Read clipboard text or image', 'high'),
    ('desktop.clipboard.set', 'Write clipboard text or image', 'high'),
    ('desktop.session.open', 'Open a persistent desktop capture session', 'high'),
    ('desktop.session.frame', 'Fetch the latest frame from a desktop session', 'high'),
    ('desktop.session.input', 'Send a batch of input events to a desktop session', 'high'),
    ('desktop.session.close', 'Close a desktop capture session', 'high');

CREATE TABLE IF NOT EXISTS desktop_sessions (
    id UUID PRIMARY KEY,
    machine_id UUID NOT NULL REFERENCES machines(id),
    ai_identity_id UUID NOT NULL REFERENCES ai_identities(id),
    status TEXT NOT NULL DEFAULT 'open'
        CHECK (status IN ('open', 'closed', 'expired')),
    display_index INT,
    fps INT NOT NULL DEFAULT 2,
    format TEXT NOT NULL DEFAULT 'png',
    max_duration_secs INT NOT NULL DEFAULT 600,
    opened_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL,
    closed_at TIMESTAMPTZ,
    helper_session_id TEXT
);

CREATE INDEX IF NOT EXISTS idx_desktop_sessions_machine_open
    ON desktop_sessions (machine_id, status)
    WHERE status = 'open';

CREATE INDEX IF NOT EXISTS idx_desktop_sessions_identity
    ON desktop_sessions (ai_identity_id, status);
