-- Copyright (C) 2026 Gaultier HUBERT
-- SPDX-License-Identifier: GPL-3.0-or-later

-- Latest rate-limit snapshot pushed by Propylaea heartbeats (replaced each heartbeat).
CREATE TABLE IF NOT EXISTS proxy_rate_limit_snapshots (
    proxy_id UUID PRIMARY KEY REFERENCES proxies (id) ON DELETE CASCADE,
    entries JSONB NOT NULL DEFAULT '[]'::jsonb,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Operator-requested unbans delivered to Propylaea on the next sync.
CREATE TABLE IF NOT EXISTS proxy_rate_limit_unbans (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    proxy_id UUID NOT NULL REFERENCES proxies (id) ON DELETE CASCADE,
    client_ip TEXT NOT NULL,
    class TEXT NOT NULL CHECK (class IN ('enroll', 'allowed', 'unrecognized')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    delivered_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS proxy_rate_limit_unbans_pending_idx
    ON proxy_rate_limit_unbans (proxy_id)
    WHERE delivered_at IS NULL;
