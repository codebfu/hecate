-- Persist desktop helper version reported by agent heartbeats.

ALTER TABLE machines
    ADD COLUMN IF NOT EXISTS desktop_version TEXT;
