INSERT INTO command_definitions (name, description, risk_level)
VALUES (
    'system.reboot',
    'Reboot the machine OS; completes after the agent goes offline then online again',
    'high'
)
ON CONFLICT (name) DO NOTHING;

ALTER TABLE command_queue
    ADD COLUMN IF NOT EXISTS reboot_phase TEXT
        CHECK (reboot_phase IS NULL OR reboot_phase IN ('initiated', 'agent_down'));

CREATE INDEX IF NOT EXISTS command_queue_reboot_phase_idx
    ON command_queue (reboot_phase)
    WHERE reboot_phase IS NOT NULL;
