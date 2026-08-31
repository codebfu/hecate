INSERT INTO command_definitions (name, description, risk_level) VALUES
  ('admin.repo.upgrade_all', 'Upgrade all installed features that track latest to the newest published version', 'high')
ON CONFLICT (name) DO UPDATE SET
  description = EXCLUDED.description,
  risk_level = EXCLUDED.risk_level;

UPDATE command_definitions
SET description = 'Refresh feature repository catalogue metadata only'
WHERE name = 'admin.repo.refresh';
