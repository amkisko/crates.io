ALTER TABLE api_mfa_challenges
    DROP CONSTRAINT IF EXISTS api_mfa_challenges_mutation_protocol_fields_check;

DROP INDEX IF EXISTS api_mfa_challenges_poll_token_unique_idx;
DROP INDEX IF EXISTS api_mfa_challenges_preflight_unique_idx;

ALTER TABLE api_mfa_challenges
    DROP COLUMN IF EXISTS receive_expires_at,
    DROP COLUMN IF EXISTS mutation_state,
    DROP COLUMN IF EXISTS poll_token,
    DROP COLUMN IF EXISTS callback_url,
    DROP COLUMN IF EXISTS allow_pending,
    DROP COLUMN IF EXISTS preflight_id;
