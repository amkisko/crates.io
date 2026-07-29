-- Browser-assisted cargo login: CLI creates a session, user picks scopes in the
-- browser, plaintext token is delivered once via poll (never shown in the UI).
CREATE TABLE cli_login_sessions (
    id VARCHAR PRIMARY KEY,
    -- Set when the browser claims/approves the session
    user_id INTEGER REFERENCES users (id) ON DELETE CASCADE,
    -- `pending` | `ready` | `consumed`
    status VARCHAR NOT NULL DEFAULT 'pending',
    -- Optional localhost port for posting the token back to the CLI
    localhost_port INTEGER,
    -- Client IP that started the session (pending-cap / forensics)
    client_ip VARCHAR,
    -- SHA-256 of normalized confirmation code from POST /cli_login; required on approve
    confirmation_code_hash BYTEA NOT NULL,
    -- Filled on approve; wiped on first successful poll
    plaintext_token VARCHAR,
    api_token_id INTEGER REFERENCES api_tokens (id) ON DELETE SET NULL,
    -- Updated on each poll; used for IP-agnostic per-session poll pacing
    last_polled_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT cli_login_sessions_status_check
        CHECK (status IN ('pending', 'ready', 'consumed')),
    CONSTRAINT cli_login_sessions_localhost_port_range
        CHECK (localhost_port IS NULL OR (localhost_port >= 1024 AND localhost_port <= 65535))
);

CREATE INDEX cli_login_sessions_expires_at_idx
    ON cli_login_sessions (expires_at);
CREATE INDEX cli_login_sessions_pending_ip_idx
    ON cli_login_sessions (client_ip)
    WHERE status = 'pending';
-- Create rate-limit COUNT(client_ip) WHERE created_at >= …
CREATE INDEX cli_login_sessions_ip_created_idx
    ON cli_login_sessions (client_ip, created_at);

COMMENT ON TABLE cli_login_sessions IS
    'Short-lived cargo login ceremonies: URL → browser scopes → one-time poll delivery';

COMMENT ON COLUMN cli_login_sessions.confirmation_code_hash IS
    'SHA-256 of normalized confirmation code from POST /cli_login; required on approve';
