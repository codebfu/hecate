INSERT INTO command_definitions (name, description, risk_level) VALUES
  ('admin.repo.sources.update', 'Update a feature repository source URL, public key, or priority', 'high')
ON CONFLICT (name) DO UPDATE SET
  description = EXCLUDED.description,
  risk_level = EXCLUDED.risk_level;
