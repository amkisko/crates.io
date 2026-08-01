-- Give each Cargo invocation its own mutation record and an independent
-- read-only polling capability.
ALTER TABLE api_mfa_challenges
    ADD COLUMN preflight_id VARCHAR,
    ADD COLUMN allow_pending BOOLEAN,
    ADD COLUMN callback_url VARCHAR,
    ADD COLUMN poll_token VARCHAR,
    ADD COLUMN mutation_state VARCHAR,
    ADD COLUMN receive_expires_at TIMESTAMPTZ;

CREATE UNIQUE INDEX api_mfa_challenges_preflight_unique_idx
    ON api_mfa_challenges (api_token_id, preflight_id)
    WHERE api_token_id IS NOT NULL AND preflight_id IS NOT NULL;

CREATE UNIQUE INDEX api_mfa_challenges_poll_token_unique_idx
    ON api_mfa_challenges (poll_token)
    WHERE poll_token IS NOT NULL;

ALTER TABLE api_mfa_challenges
    ADD CONSTRAINT api_mfa_challenges_mutation_protocol_fields_check CHECK (
        preflight_id IS NOT NULL
        AND descriptor_json IS NOT NULL
        AND allow_pending IS NOT NULL
        AND poll_token IS NOT NULL
        AND mutation_state IN (
            'pending',
            'ready',
            'receiving',
            'executing',
            'terminal',
            'consumed',
            'denied',
            'expired'
        )
    ) NOT VALID;

COMMENT ON COLUMN api_mfa_challenges.preflight_id IS
    'Cargo-generated logical invocation identifier used only for preflight retry deduplication';
COMMENT ON COLUMN api_mfa_challenges.callback_url IS
    'Exact loopback callback URL registered by Cargo; delivery metadata, not mutation authority';
COMMENT ON COLUMN api_mfa_challenges.poll_token IS
    'Short-lived read-only capability for observing mutation authorization status';
COMMENT ON COLUMN api_mfa_challenges.mutation_state IS
    'Lifecycle state for a version 1 mutation authorization record';
COMMENT ON COLUMN api_mfa_challenges.receive_expires_at IS
    'Deadline for completing or retrying a claimed mutation request body';
