ALTER TABLE api_mfa_challenges
    ADD COLUMN mutation_fingerprint BYTEA;

UPDATE api_mfa_challenges
SET mutation_fingerprint = decode(repeat('00', 32), 'hex');

ALTER TABLE api_mfa_challenges
    ALTER COLUMN mutation_fingerprint SET NOT NULL;

COMMENT ON COLUMN api_mfa_challenges.mutation_fingerprint IS
    'SHA-256 binding the challenge to the exact server-parsed mutation';
