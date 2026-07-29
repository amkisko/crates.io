-- Server-checked cookie invalidation (logout-all / MFA enable bumps this).
ALTER TABLE users
    ADD COLUMN session_generation INTEGER NOT NULL DEFAULT 0;
COMMENT ON COLUMN users.session_generation IS
    'Bumped to invalidate all cargo_session cookies that still carry an older generation';

-- Challenge grants bind to the API token that created the challenge.
-- NULL api_token_id = Authorize wildcard (covers cookie and any of the user's tokens).
ALTER TABLE api_mfa_grants
    ADD COLUMN api_token_id INTEGER REFERENCES api_tokens (id) ON DELETE CASCADE;
CREATE INDEX api_mfa_grants_user_token_expires_idx
    ON api_mfa_grants (user_id, api_token_id, expires_at);
COMMENT ON COLUMN api_mfa_grants.api_token_id IS
    'When set, grant covers only this API token; NULL is Authorize wildcard for cookie and any token';
