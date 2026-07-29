ALTER TABLE api_mfa_challenges
    DROP COLUMN IF EXISTS localhost_callback_secret_hash;
