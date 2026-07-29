DROP INDEX IF EXISTS api_mfa_grants_user_token_expires_idx;
ALTER TABLE api_mfa_grants DROP COLUMN IF EXISTS api_token_id;
ALTER TABLE users DROP COLUMN IF EXISTS session_generation;
