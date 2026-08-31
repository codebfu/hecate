-- Add authz_provenance enum value in its own migration (PostgreSQL forbids
-- using a new enum value in the same transaction as ADD VALUE).

ALTER TYPE authz_provenance ADD VALUE IF NOT EXISTS 'system';
