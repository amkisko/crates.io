ALTER TABLE api_mfa_challenges
    ADD COLUMN idempotent_final BOOLEAN NOT NULL DEFAULT FALSE;

ALTER TABLE api_mfa_challenges
    ADD CONSTRAINT api_mfa_challenges_response_body_size_check CHECK (
        response_body IS NULL OR OCTET_LENGTH(response_body) <= 1048576
    );

COMMENT ON COLUMN api_mfa_challenges.idempotent_final IS
    'Whether this record activated the idempotent-final extension';

CREATE INDEX api_mfa_challenges_completed_at_idx
    ON api_mfa_challenges (completed_at)
    WHERE completed_at IS NOT NULL;
