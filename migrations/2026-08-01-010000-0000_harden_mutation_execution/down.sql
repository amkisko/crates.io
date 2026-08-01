DROP INDEX IF EXISTS api_mfa_challenges_completed_at_idx;

ALTER TABLE api_mfa_challenges
    DROP CONSTRAINT IF EXISTS api_mfa_challenges_response_body_size_check,
    DROP COLUMN IF EXISTS idempotent_final;
