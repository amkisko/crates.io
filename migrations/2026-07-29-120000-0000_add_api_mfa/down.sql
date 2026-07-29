DROP TABLE IF EXISTS api_mfa_email_otps;
DROP TABLE IF EXISTS webauthn_ceremony_states;
DROP TABLE IF EXISTS api_mfa_challenges;
DROP TABLE IF EXISTS api_mfa_grants;
DROP TABLE IF EXISTS webauthn_credentials;
ALTER TABLE users DROP COLUMN IF EXISTS api_mfa_enabled;
