-- Stage a new address while keeping the verified inbox for MFA OTP recovery
-- until the pending address is confirmed via /api/v1/confirm/{token}.
ALTER TABLE emails
    ADD COLUMN IF NOT EXISTS pending_email VARCHAR;

COMMENT ON COLUMN emails.pending_email IS
    'Unverified replacement address; email/verified stay current until confirm';
