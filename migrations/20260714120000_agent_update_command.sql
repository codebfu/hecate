INSERT INTO command_definitions (name, description, risk_level)
VALUES ('agent.update', 'Download and apply the latest signed agent release from the server', 'high')
ON CONFLICT (name) DO NOTHING;
