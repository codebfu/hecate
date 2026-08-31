-- Persist agent process uptime so system.reboot can detect a restart even when
-- the offline window is shorter than OFFLINE_AFTER_SECS (fast VM reboots).
ALTER TABLE machines
    ADD COLUMN IF NOT EXISTS agent_uptime_secs BIGINT;

COMMENT ON COLUMN machines.agent_uptime_secs IS
    'Last agent process uptime_secs from heartbeat; used to detect restarts for system.reboot';
