-- Default feature installs track the newest published version.
-- Explicit pins only when an operator/AI requests a concrete version.
ALTER TABLE installed_features
  ADD COLUMN IF NOT EXISTS track_latest BOOLEAN NOT NULL DEFAULT true;

-- Remove stub pins created by the agent_releases → installed_features migration.
-- Those were not operator-requested installs and had empty feature_json.
DELETE FROM installed_features
WHERE feature_json = '{}'::jsonb;

-- Existing real installs follow latest unless later re-pinned with an explicit version.
UPDATE installed_features
SET track_latest = true;

UPDATE command_definitions
SET description = CASE name
  WHEN 'admin.repo.install' THEN 'Install a feature (tracks latest unless version is set)'
  WHEN 'admin.repo.upgrade' THEN 'Upgrade a feature or pin an explicit version'
  WHEN 'admin.repo.refresh' THEN 'Refresh feature repository metadata and follow latest installs'
  ELSE description
END
WHERE name IN ('admin.repo.install', 'admin.repo.upgrade', 'admin.repo.refresh');
