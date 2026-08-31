-- Distinguish agent vs desktop helper self-update artifacts.
ALTER TABLE agent_releases
  ADD COLUMN component TEXT NOT NULL DEFAULT 'agent';

ALTER TABLE agent_releases
  DROP CONSTRAINT agent_releases_pkey;

ALTER TABLE agent_releases
  ADD CONSTRAINT agent_releases_pkey PRIMARY KEY (version, os, arch, component);

ALTER TABLE agent_releases
  ADD CONSTRAINT agent_releases_component_check
  CHECK (component IN ('agent', 'desktop'));
