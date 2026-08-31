-- Agent-reported health from heartbeats (distinct from connectivity / last_seen_at).
-- An agent can keep heartbeating while the pull loop is stuck; healthy=false surfaces that.
-- Busy with a long command remains healthy=true.

ALTER TABLE machines
    ADD COLUMN IF NOT EXISTS agent_healthy BOOLEAN,
    ADD COLUMN IF NOT EXISTS agent_secs_since_last_pull BIGINT,
    ADD COLUMN IF NOT EXISTS agent_current_command_id UUID;

COMMENT ON COLUMN machines.agent_healthy IS
    'Agent-reported global health from heartbeat (pull can drain queue, or busy with a command). NULL = older agent / unknown.';
COMMENT ON COLUMN machines.agent_secs_since_last_pull IS
    'Seconds since last successful pull as reported by the agent heartbeat.';
COMMENT ON COLUMN machines.agent_current_command_id IS
    'Command the agent reports as currently executing (when busy).';
