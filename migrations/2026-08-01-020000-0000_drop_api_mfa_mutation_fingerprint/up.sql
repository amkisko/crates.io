-- Exact mutation binding is represented by descriptor_json plus the separately
-- stored method, target, body digest, and body size. This digest duplicated that
-- state and had no consumer.
ALTER TABLE api_mfa_challenges
    DROP COLUMN mutation_fingerprint;
