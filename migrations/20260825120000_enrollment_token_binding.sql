-- Bind enrollment tokens to existing machines/proxies for re-enroll flows.

ALTER TABLE enrollment_tokens
    ADD COLUMN IF NOT EXISTS bound_machine_id UUID REFERENCES machines(id);

ALTER TABLE proxy_enrollment_tokens
    ADD COLUMN IF NOT EXISTS bound_proxy_id UUID REFERENCES proxies(id);
