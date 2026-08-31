CREATE TABLE repo_sources (
  id TEXT PRIMARY KEY,
  url TEXT NOT NULL,
  public_key_b64 TEXT NOT NULL,
  enabled BOOLEAN NOT NULL DEFAULT true,
  priority INT NOT NULL DEFAULT 0,
  last_sync_at TIMESTAMPTZ,
  last_error TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE installed_features (
  id TEXT PRIMARY KEY,
  pinned_version TEXT NOT NULL,
  source_id TEXT NOT NULL REFERENCES repo_sources(id),
  installed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  feature_json JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE TABLE feature_artifact_cache (
  feature_id TEXT NOT NULL,
  version TEXT NOT NULL,
  os TEXT NOT NULL,
  arch TEXT NOT NULL,
  filename TEXT NOT NULL,
  sha256 TEXT NOT NULL,
  local_path TEXT NOT NULL,
  PRIMARY KEY (feature_id, version, os, arch)
);

INSERT INTO repo_sources (id, url, public_key_b64, enabled, priority)
VALUES (
  'official',
  'https://repo.hecate-mcp.com',
  'DUmxIh9XT8jpvDyeQ9QTmmC3ddC4xr9abA3faSNusqY=',
  true,
  100
)
ON CONFLICT DO NOTHING;

INSERT INTO command_definitions (name, description, risk_level) VALUES
  ('admin.repo.sources.list', 'List configured feature repository sources', 'low'),
  ('admin.repo.sources.add', 'Add a feature repository source', 'high'),
  ('admin.repo.sources.enable', 'Enable a feature repository source', 'high'),
  ('admin.repo.sources.disable', 'Disable a feature repository source', 'high'),
  ('admin.repo.sources.remove', 'Remove a feature repository source', 'high'),
  ('admin.repo.list', 'List available and installed features', 'low'),
  ('admin.repo.install', 'Install and pin a feature version', 'high'),
  ('admin.repo.upgrade', 'Upgrade a pinned feature version', 'high'),
  ('admin.repo.uninstall', 'Uninstall a feature', 'high'),
  ('admin.repo.status', 'Show feature repository status', 'low'),
  ('admin.repo.refresh', 'Refresh feature repository metadata', 'high')
ON CONFLICT (name) DO UPDATE SET
  description = EXCLUDED.description,
  risk_level = EXCLUDED.risk_level;

INSERT INTO installed_features (id, pinned_version, source_id, feature_json)
SELECT component, max(version), 'official', '{}'::jsonb
FROM agent_releases
WHERE component IN ('agent', 'desktop', 'proxmox')
GROUP BY component
ON CONFLICT (id) DO NOTHING;

DELETE FROM command_definitions
WHERE NOT EXISTS (SELECT 1 FROM agent_releases)
  AND name NOT LIKE 'permissions.%'
  AND name NOT LIKE 'admin.permissions.%'
  AND name <> 'admin.audit.list'
  AND name NOT LIKE 'admin.queue.%'
  AND name NOT LIKE 'admin.repo.%';
