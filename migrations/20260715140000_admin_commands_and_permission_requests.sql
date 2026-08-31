CREATE TYPE permission_request_status AS ENUM ('pending', 'approved', 'rejected');

CREATE TABLE ai_permission_requests (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  ai_identity_id UUID NOT NULL REFERENCES ai_identities(id),
  requested_rules JSONB NOT NULL,
  reason TEXT,
  review_reason TEXT,
  status permission_request_status NOT NULL DEFAULT 'pending',
  reviewed_by TEXT,
  reviewed_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX ai_permission_requests_one_pending
  ON ai_permission_requests (ai_identity_id)
  WHERE status = 'pending';

INSERT INTO command_definitions (name, description, risk_level) VALUES
  ('permissions.request', 'Request permanent permission changes (operator approval)', 'low'),
  ('admin.permissions.read', 'Read AI permission rules', 'low'),
  ('admin.permissions.requests.list', 'List permission change requests', 'low'),
  ('admin.permissions.request.approve', 'Approve permission requests (not own)', 'high'),
  ('admin.permissions.request.reject', 'Reject permission requests', 'high'),
  ('admin.audit.list', 'Read audit log', 'low'),
  ('admin.queue.list', 'Read fleet action queue', 'low'),
  ('admin.queue.approve', 'Approve pending commands (not own)', 'high'),
  ('admin.queue.cancel', 'Cancel pending or queued commands', 'high')
ON CONFLICT (name) DO NOTHING;
