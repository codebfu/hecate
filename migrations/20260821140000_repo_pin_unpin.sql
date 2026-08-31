INSERT INTO command_definitions (name, description, risk_level) VALUES
  ('admin.repo.pin', 'Pin an installed feature to an explicit version', 'high'),
  ('admin.repo.unpin', 'Remove a feature version pin and resume tracking latest', 'high')
ON CONFLICT (name) DO UPDATE SET
  description = EXCLUDED.description,
  risk_level = EXCLUDED.risk_level;
