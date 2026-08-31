-- Track feature-index generation time so older/replayed indexes are rejected.
ALTER TABLE repo_sources
  ADD COLUMN IF NOT EXISTS last_index_generated_at TIMESTAMPTZ;
