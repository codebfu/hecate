-- Built-in system catalog entities (enum value 'system' added in prior migration).

INSERT INTO fleet_scopes (id, name, description, provenance, request_scoped)
VALUES (
    '00000000-0000-4000-8000-000000000004',
    'All',
    'System scope: includes every machine in the fleet automatically',
    'system',
    false
)
ON CONFLICT (id) DO NOTHING;

INSERT INTO fleet_scope_tags (fleet_scope_id, tag)
VALUES ('00000000-0000-4000-8000-000000000004', '__hecate_all_machines__')
ON CONFLICT DO NOTHING;

INSERT INTO capability_profiles (
    id,
    name,
    description,
    provenance,
    request_scoped,
    allowed_commands,
    allowed_admin_commands,
    shell_policy,
    elevation_policy,
    max_output_bytes,
    max_file_bytes,
    timeout_secs,
    max_concurrent
) VALUES (
    '00000000-0000-4000-8000-000000000005',
    'All user commands',
    'System profile: allows every agent/platform command',
    'system',
    false,
    ARRAY['*']::TEXT[],
    ARRAY[]::TEXT[],
    '{"allowed_binaries":["*"],"allowed_cwd":["*"],"allowed_env":[]}'::jsonb,
    '{"enabled":true,"allowed_binaries":["*"]}'::jsonb,
    1048576,
    52428800,
    30,
    4
)
ON CONFLICT (id) DO NOTHING;

INSERT INTO capability_profiles (
    id,
    name,
    description,
    provenance,
    request_scoped,
    allowed_commands,
    allowed_admin_commands,
    shell_policy,
    elevation_policy,
    max_output_bytes,
    max_file_bytes,
    timeout_secs,
    max_concurrent
) VALUES (
    '00000000-0000-4000-8000-000000000006',
    'All admin commands',
    'System profile: allows every admin command',
    'system',
    false,
    ARRAY[]::TEXT[],
    ARRAY['*']::TEXT[],
    '{}'::jsonb,
    '{}'::jsonb,
    1048576,
    52428800,
    30,
    4
)
ON CONFLICT (id) DO NOTHING;
