ALTER TABLE api_mfa_challenges
    ADD COLUMN localhost_callback_secret_hash BYTEA;

COMMENT ON COLUMN api_mfa_challenges.localhost_callback_secret_hash IS
    'SHA-256 of the client-held secret required to replace localhost_port';
