-- Canonical fleet-update signatures (legacy GitLab-compatible) for agents
-- that do not yet verify feature-repo content .sig files.
ALTER TABLE feature_artifact_cache
  ADD COLUMN IF NOT EXISTS update_signature TEXT;
