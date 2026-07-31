ALTER TABLE api_mfa_challenges
    DROP CONSTRAINT IF EXISTS api_mfa_challenges_response_fields_check,
    DROP CONSTRAINT IF EXISTS api_mfa_challenges_preflight_fields_check,
    DROP COLUMN IF EXISTS completed_at,
    DROP COLUMN IF EXISTS response_body,
    DROP COLUMN IF EXISTS response_headers,
    DROP COLUMN IF EXISTS response_status,
    DROP COLUMN IF EXISTS request_size,
    DROP COLUMN IF EXISTS request_sha256,
    DROP COLUMN IF EXISTS request_endpoint,
    DROP COLUMN IF EXISTS request_method,
    DROP COLUMN IF EXISTS descriptor_json;
