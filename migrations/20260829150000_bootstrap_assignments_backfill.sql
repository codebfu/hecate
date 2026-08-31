-- Auto-assign the hidden bootstrap grant to every active AI identity.

INSERT INTO ai_grant_assignments (
    ai_identity_id,
    access_grant_id,
    requires_approval_for_shell,
    requires_approval_for_elevated,
    enabled
)
SELECT
    ai.id,
    '00000000-0000-4000-8000-000000000003'::uuid,
    true,
    true,
    true
FROM ai_identities ai
WHERE ai.deleted_at IS NULL
ON CONFLICT (ai_identity_id, access_grant_id) DO NOTHING;
