-- Browser-assisted cargo login: CLI creates a session, user picks scopes in the
-- browser, token is delivered once via poll (never shown in the UI).
-- safety-assured:start
--
-- This table and its indexes are created together while the table is empty, so
-- non-concurrent index creation cannot block live table writes. Integer foreign
-- keys intentionally match the referenced integer IDs.
CREATE TABLE IF NOT EXISTS cli_login_sessions (
    id VARCHAR PRIMARY KEY,
    -- Set when the browser claims/approves the session
    user_id INTEGER REFERENCES users (id) ON DELETE CASCADE,
    -- `pending` | `ready` | `consumed`
    status VARCHAR NOT NULL DEFAULT 'pending',
    -- Client IP that started the session (pending-cap / forensics)
    client_ip VARCHAR,
    -- SHA-256 of normalized confirmation code from POST /cli_login; required on approve
    confirmation_code_hash BYTEA NOT NULL,
    -- SHA-256 of poll secret returned only to the CLI starter; required on GET poll
    poll_secret_hash BYTEA NOT NULL,
    -- Encrypted redeem blob filled on approve; wiped on first successful poll
    sealed_token VARCHAR,
    api_token_id INTEGER REFERENCES api_tokens (id) ON DELETE SET NULL,
    -- Updated on each poll; used for IP-agnostic per-session poll pacing
    last_polled_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT cli_login_sessions_status_check
        CHECK (status IN ('pending', 'ready', 'consumed'))
);

CREATE INDEX IF NOT EXISTS cli_login_sessions_expires_at_idx
    ON cli_login_sessions (expires_at);
CREATE INDEX IF NOT EXISTS cli_login_sessions_pending_ip_idx
    ON cli_login_sessions (client_ip)
    WHERE status = 'pending';
-- Create rate-limit COUNT(client_ip) WHERE created_at >= …
CREATE INDEX IF NOT EXISTS cli_login_sessions_ip_created_idx
    ON cli_login_sessions (client_ip, created_at);

COMMENT ON TABLE cli_login_sessions IS
    'Short-lived cargo login ceremonies: URL → browser scopes → one-time poll delivery';

COMMENT ON COLUMN cli_login_sessions.confirmation_code_hash IS
    'SHA-256 of normalized confirmation code from POST /cli_login; required on approve';

COMMENT ON COLUMN cli_login_sessions.poll_secret_hash IS
    'SHA-256 of poll secret returned only to the CLI starter; required on GET poll';

COMMENT ON COLUMN cli_login_sessions.sealed_token IS
    'Sealed (encrypted) redeem blob between approve and first successful poll; never raw API token plaintext';

-- safety-assured:end
