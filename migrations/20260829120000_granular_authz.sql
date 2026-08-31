-- Breaking migration: granular authorization model (Hecate 1.2.0)

CREATE TYPE tag_match_mode AS ENUM ('any', 'all');
CREATE TYPE authz_provenance AS ENUM ('operator', 'permission_request', 'import', 'seed');
CREATE TYPE permission_request_class AS ENUM ('standard', 'admin');

CREATE TABLE fleet_scopes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    tag_match_mode tag_match_mode NOT NULL DEFAULT 'any',
    provenance authz_provenance NOT NULL DEFAULT 'operator',
    request_scoped BOOLEAN NOT NULL DEFAULT false,
    owner_ai_identity_id UUID REFERENCES ai_identities(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE fleet_scope_machines (
    fleet_scope_id UUID NOT NULL REFERENCES fleet_scopes(id) ON DELETE CASCADE,
    machine_id UUID NOT NULL REFERENCES machines(id) ON DELETE CASCADE,
    PRIMARY KEY (fleet_scope_id, machine_id)
);

CREATE TABLE fleet_scope_tags (
    fleet_scope_id UUID NOT NULL REFERENCES fleet_scopes(id) ON DELETE CASCADE,
    tag TEXT NOT NULL,
    PRIMARY KEY (fleet_scope_id, tag)
);

CREATE TABLE capability_profiles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    provenance authz_provenance NOT NULL DEFAULT 'operator',
    request_scoped BOOLEAN NOT NULL DEFAULT false,
    owner_ai_identity_id UUID REFERENCES ai_identities(id) ON DELETE SET NULL,
    allowed_commands TEXT[] NOT NULL DEFAULT '{}',
    allowed_admin_commands TEXT[] NOT NULL DEFAULT '{}',
    shell_policy JSONB NOT NULL DEFAULT '{}',
    elevation_policy JSONB NOT NULL DEFAULT '{}',
    max_output_bytes INT NOT NULL DEFAULT 1048576,
    max_file_bytes INT NOT NULL DEFAULT 52428800,
    timeout_secs INT NOT NULL DEFAULT 30,
    max_concurrent INT NOT NULL DEFAULT 4,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE access_grants (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    provenance authz_provenance NOT NULL DEFAULT 'operator',
    request_scoped BOOLEAN NOT NULL DEFAULT false,
    owner_ai_identity_id UUID REFERENCES ai_identities(id) ON DELETE SET NULL,
    fleet_scope_id UUID NOT NULL REFERENCES fleet_scopes(id) ON DELETE RESTRICT,
    capability_profile_id UUID NOT NULL REFERENCES capability_profiles(id) ON DELETE RESTRICT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE ai_grant_assignments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    ai_identity_id UUID NOT NULL REFERENCES ai_identities(id) ON DELETE CASCADE,
    access_grant_id UUID NOT NULL REFERENCES access_grants(id) ON DELETE RESTRICT,
    requires_approval_for_shell BOOLEAN NOT NULL DEFAULT true,
    requires_approval_for_elevated BOOLEAN NOT NULL DEFAULT true,
    enabled BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (ai_identity_id, access_grant_id)
);

ALTER TABLE command_queue
    ADD COLUMN matched_grant_assignment_id UUID REFERENCES ai_grant_assignments(id) ON DELETE SET NULL,
    ADD COLUMN execution_policy_snapshot JSONB NOT NULL DEFAULT '{}';

ALTER TABLE ai_permission_requests
    ADD COLUMN requested_changes JSONB NOT NULL DEFAULT '{}',
    ADD COLUMN request_class permission_request_class NOT NULL DEFAULT 'standard';

-- Breaking: legacy permission requests cannot be migrated to the new model.
DELETE FROM ai_permission_requests;

ALTER TABLE ai_permission_requests
    DROP COLUMN requested_rules;

ALTER TABLE ai_permission_requests
    ALTER COLUMN reason SET NOT NULL;

DROP INDEX IF EXISTS ai_permission_requests_one_pending;

CREATE UNIQUE INDEX ai_permission_requests_one_pending_per_class
    ON ai_permission_requests (ai_identity_id, request_class)
    WHERE status = 'pending';

DROP TABLE ai_permissions;

ALTER TABLE ai_identities
    DROP COLUMN IF EXISTS requires_approval_for_shell,
    DROP COLUMN IF EXISTS requires_approval_for_elevated;

-- Seed minimal catalog for post-migration reconfiguration
INSERT INTO fleet_scopes (id, name, description, provenance, request_scoped)
VALUES (
    '00000000-0000-4000-8000-000000000001',
    'Empty fleet scope',
    'Default empty scope for manual reconfiguration after migration',
    'seed',
    false
);

INSERT INTO capability_profiles (
    id,
    name,
    description,
    provenance,
    request_scoped,
    allowed_commands,
    allowed_admin_commands
) VALUES (
    '00000000-0000-4000-8000-000000000002',
    'Read-only bootstrap',
    'system.info and permissions.request only',
    'seed',
    false,
    ARRAY['system.info', 'permissions.request'],
    ARRAY[]::TEXT[]
);

INSERT INTO access_grants (
    id,
    name,
    description,
    provenance,
    request_scoped,
    fleet_scope_id,
    capability_profile_id
) VALUES (
    '00000000-0000-4000-8000-000000000003',
    'Bootstrap read-only grant',
    'Assign to AI identities after migration to restore basic access',
    'seed',
    false,
    '00000000-0000-4000-8000-000000000001',
    '00000000-0000-4000-8000-000000000002'
);

INSERT INTO command_definitions (name, description, risk_level) VALUES
  ('admin.authz.catalog', 'Aggregated authz catalog', 'low'),
  ('admin.authz.fleet_scopes.list', 'List fleet scopes', 'low'),
  ('admin.authz.fleet_scopes.read', 'Read fleet scope detail', 'low'),
  ('admin.authz.fleet_scopes.preview', 'Preview fleet scope membership', 'low'),
  ('admin.authz.fleet_scopes.create', 'Create fleet scope', 'high'),
  ('admin.authz.fleet_scopes.update', 'Update fleet scope', 'high'),
  ('admin.authz.fleet_scopes.delete', 'Delete fleet scope', 'high'),
  ('admin.authz.capability_profiles.list', 'List capability profiles', 'low'),
  ('admin.authz.capability_profiles.read', 'Read capability profile', 'low'),
  ('admin.authz.capability_profiles.create', 'Create capability profile', 'high'),
  ('admin.authz.capability_profiles.update', 'Update capability profile', 'high'),
  ('admin.authz.capability_profiles.delete', 'Delete capability profile', 'high'),
  ('admin.authz.access_grants.list', 'List access grants', 'low'),
  ('admin.authz.access_grants.read', 'Read access grant', 'low'),
  ('admin.authz.access_grants.create', 'Create access grant', 'high'),
  ('admin.authz.access_grants.update', 'Update access grant', 'high'),
  ('admin.authz.access_grants.delete', 'Delete access grant', 'high'),
  ('admin.authz.assignments.read', 'Read grant assignments', 'low'),
  ('admin.authz.assignments.add', 'Add grant assignments', 'high'),
  ('admin.authz.assignments.remove', 'Remove grant assignments', 'high'),
  ('admin.authz.effective_rights.read', 'Read effective rights matrix', 'low')
ON CONFLICT (name) DO NOTHING;

DELETE FROM command_definitions WHERE name = 'admin.permissions.read';
