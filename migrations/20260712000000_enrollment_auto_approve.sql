INSERT INTO server_settings (key, value) VALUES
    ('enrollment_auto_approve', 'false')
ON CONFLICT (key) DO NOTHING;
