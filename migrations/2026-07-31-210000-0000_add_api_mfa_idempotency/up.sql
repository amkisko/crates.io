-- Bind API MFA challenges to raw preflight descriptors and retain terminal
-- responses for Cargo-Mutation-Id replay.
ALTER TABLE api_mfa_challenges
    ADD COLUMN descriptor_json JSONB,
    ADD COLUMN request_method VARCHAR,
    ADD COLUMN request_endpoint VARCHAR,
    ADD COLUMN request_sha256 BYTEA,
    ADD COLUMN request_size BIGINT,
    ADD COLUMN response_status INTEGER,
    ADD COLUMN response_headers JSONB,
    ADD COLUMN response_body BYTEA,
    ADD COLUMN completed_at TIMESTAMPTZ;

COMMENT ON COLUMN api_mfa_challenges.descriptor_json IS
    'Validated versioned mutation descriptor supplied during preflight';
COMMENT ON COLUMN api_mfa_challenges.response_body IS
    'Terminal response body replayed for idempotent mutation retries';

ALTER TABLE api_mfa_challenges
    ADD CONSTRAINT api_mfa_challenges_preflight_fields_check CHECK (
        descriptor_json IS NULL OR (
            request_method IS NOT NULL
            AND request_endpoint IS NOT NULL
            AND request_sha256 IS NOT NULL
            AND OCTET_LENGTH(request_sha256) = 32
            AND request_size IS NOT NULL
            AND request_size >= 0
        )
    ) NOT VALID,
    ADD CONSTRAINT api_mfa_challenges_response_fields_check CHECK (
        completed_at IS NULL OR (
            response_status BETWEEN 100 AND 599
            AND response_headers IS NOT NULL
            AND response_body IS NOT NULL
        )
    ) NOT VALID;
