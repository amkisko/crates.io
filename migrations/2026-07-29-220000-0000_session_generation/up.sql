-- Server-checked cookie invalidation (logout-all / MFA enable bumps this).
ALTER TABLE users
    ADD COLUMN IF NOT EXISTS session_generation INTEGER NOT NULL DEFAULT 0;
COMMENT ON COLUMN users.session_generation IS
    'Bumped to invalidate all cargo_session cookies that still carry an older generation';
