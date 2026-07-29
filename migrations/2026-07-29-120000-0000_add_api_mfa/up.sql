-- Opt-in API MFA: when enabled, publish/yank/owner changes (API token or cookie)
-- require a recent passkey verification (short-lived grant) or a one-time OTP.
ALTER TABLE users
    ADD COLUMN api_mfa_enabled BOOLEAN NOT NULL DEFAULT FALSE;
COMMENT ON COLUMN users.api_mfa_enabled IS
    'When true, publish/yank/change-owners (token or cookie) require passkey step-up';

CREATE TABLE webauthn_credentials (
    id BIGSERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    -- Raw WebAuthn credential ID (unique across users)
    credential_id BYTEA NOT NULL,
    -- Serialized webauthn_rs::prelude::Passkey
    passkey_json JSONB NOT NULL,
    name VARCHAR NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used_at TIMESTAMPTZ
);
CREATE UNIQUE INDEX webauthn_credentials_credential_id_idx
    ON webauthn_credentials (credential_id);
CREATE INDEX webauthn_credentials_user_id_idx
    ON webauthn_credentials (user_id);
COMMENT ON TABLE webauthn_credentials IS
    'Passkeys / WebAuthn credentials registered for API MFA step-up';

-- Short-lived authorization after a successful passkey verification.
-- NULL operation = wildcard (manual "Authorize for 15 minutes").
CREATE TABLE api_mfa_grants (
    id BIGSERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    -- When set, grant only covers this operation; NULL means any operation.
    operation VARCHAR,
    -- When set with operation, grant only covers this crate.
    crate_name VARCHAR,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX api_mfa_grants_user_expires_idx
    ON api_mfa_grants (user_id, expires_at);
CREATE INDEX api_mfa_grants_expires_at_idx
    ON api_mfa_grants (expires_at);
COMMENT ON TABLE api_mfa_grants IS
    'Time-bounded grants issued after passkey verification for API MFA';
COMMENT ON COLUMN api_mfa_grants.operation IS
    'When set, grant only covers this operation; NULL means any operation (manual authorize)';
COMMENT ON COLUMN api_mfa_grants.crate_name IS
    'When set with operation, grant only covers this crate; NULL with operation is unused';

-- CLI challenge flow (RubyGems-style): create challenge → verify passkey in browser → OTP.
CREATE TABLE api_mfa_challenges (
    -- Public opaque token used in verification URLs
    id VARCHAR PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    api_token_id INTEGER REFERENCES api_tokens (id) ON DELETE SET NULL,
    -- Dangerous operation that triggered this challenge (publish, yank, change-owners, …)
    operation VARCHAR NOT NULL,
    -- Optional crate involved in the operation
    crate_name VARCHAR,
    -- Optional localhost port for posting the OTP back to the CLI
    localhost_port INTEGER,
    -- Serialized PasskeyAuthentication state while the ceremony is in progress
    auth_state_json JSONB,
    -- SHA-256 of the one-time OTP, set after successful passkey verification
    hashed_otp BYTEA,
    verified_at TIMESTAMPTZ,
    otp_consumed_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT api_mfa_challenges_localhost_port_range
        CHECK (localhost_port IS NULL OR (localhost_port >= 1024 AND localhost_port <= 65535))
);
CREATE INDEX api_mfa_challenges_user_id_idx
    ON api_mfa_challenges (user_id);
CREATE INDEX api_mfa_challenges_pending_op_idx
    ON api_mfa_challenges (api_token_id, operation, crate_name, expires_at)
    WHERE verified_at IS NULL;
CREATE UNIQUE INDEX api_mfa_challenges_pending_unique_idx
    ON api_mfa_challenges (api_token_id, operation, (COALESCE(crate_name, '')))
    WHERE verified_at IS NULL AND api_token_id IS NOT NULL;
CREATE INDEX api_mfa_challenges_pending_user_idx
    ON api_mfa_challenges (user_id)
    WHERE verified_at IS NULL;
CREATE INDEX api_mfa_challenges_expires_at_idx
    ON api_mfa_challenges (expires_at);
COMMENT ON TABLE api_mfa_challenges IS
    'Short-lived API MFA operation challenges for CLI passkey acknowledgment';
COMMENT ON COLUMN api_mfa_challenges.operation IS
    'Dangerous operation that triggered this challenge (publish, yank, change-owners, …)';
COMMENT ON COLUMN api_mfa_challenges.crate_name IS
    'Optional crate involved in the operation';

-- Server-side WebAuthn ceremony state (registration / manual authorize).
-- Keeps PasskeyRegistration / PasskeyAuthentication off client session cookies.
CREATE TABLE webauthn_ceremony_states (
    id BIGSERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    -- `registration` or `authentication`
    kind VARCHAR NOT NULL,
    state_json JSONB NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT webauthn_ceremony_states_kind_check
        CHECK (kind IN ('registration', 'authentication'))
);
CREATE UNIQUE INDEX webauthn_ceremony_states_user_kind_idx
    ON webauthn_ceremony_states (user_id, kind);
CREATE INDEX webauthn_ceremony_states_expires_at_idx
    ON webauthn_ceremony_states (expires_at);
COMMENT ON TABLE webauthn_ceremony_states IS
    'In-progress WebAuthn ceremony state for API MFA register/authorize flows';

-- Email OTP for API MFA bootstrap / recovery (enable, disable, first/recovery passkey enroll).
-- Not used as a factor for publish/yank/owner challenges (those remain passkey-only).
CREATE TABLE api_mfa_email_otps (
    id BIGSERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    -- SHA-256 of the plaintext OTP
    hashed_otp BYTEA NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- At most one unused non-expired OTP per user (resend replaces).
CREATE UNIQUE INDEX api_mfa_email_otps_active_user_idx
    ON api_mfa_email_otps (user_id)
    WHERE consumed_at IS NULL;
CREATE INDEX api_mfa_email_otps_expires_at_idx
    ON api_mfa_email_otps (expires_at);

COMMENT ON TABLE api_mfa_email_otps IS
    'Short-lived email OTPs for API MFA enable/disable and passkey enrollment recovery';
