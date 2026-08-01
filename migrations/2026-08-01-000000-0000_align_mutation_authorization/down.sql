ALTER TABLE api_mfa_challenges
    DROP CONSTRAINT IF EXISTS api_mfa_challenges_mutation_protocol_fields_check;

DROP INDEX IF EXISTS api_mfa_challenges_poll_token_unique_idx;
DROP INDEX IF EXISTS api_mfa_challenges_manual_pending_unique_idx;
DROP INDEX IF EXISTS api_mfa_challenges_preflight_unique_idx;

ALTER TABLE api_mfa_challenges
    DROP COLUMN IF EXISTS poll_token,
    DROP COLUMN IF EXISTS callback_url,
    DROP COLUMN IF EXISTS allow_pending,
    DROP COLUMN IF EXISTS preflight_id;

CREATE UNIQUE INDEX api_mfa_challenges_pending_unique_idx
    ON api_mfa_challenges (
        api_token_id,
        operation,
        (COALESCE(crate_name, '')),
        mutation_fingerprint
    )
    WHERE verified_at IS NULL AND api_token_id IS NOT NULL;
