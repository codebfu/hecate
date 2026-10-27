-- Allow multiple installers per (feature, version, os, arch), e.g. linux deb + rpm.
ALTER TABLE feature_artifact_cache
  ADD COLUMN installer_type TEXT;

UPDATE feature_artifact_cache
SET installer_type = CASE
  WHEN lower(filename) LIKE '%.rpm' THEN 'rpm'
  WHEN lower(filename) LIKE '%.msi' THEN 'msi'
  WHEN lower(filename) LIKE '%.pkg' THEN 'pkg'
  WHEN lower(filename) LIKE '%.deb' THEN 'deb'
  ELSE 'raw'
END
WHERE installer_type IS NULL;

ALTER TABLE feature_artifact_cache
  ALTER COLUMN installer_type SET DEFAULT 'deb';

ALTER TABLE feature_artifact_cache
  ALTER COLUMN installer_type SET NOT NULL;

ALTER TABLE feature_artifact_cache
  DROP CONSTRAINT feature_artifact_cache_pkey;

ALTER TABLE feature_artifact_cache
  ADD PRIMARY KEY (feature_id, version, os, arch, installer_type);
