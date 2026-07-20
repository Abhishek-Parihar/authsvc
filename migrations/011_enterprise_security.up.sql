-- Enterprise security: privacy, MFA policy, SaaS metadata, SCIM tokens

ALTER TABLE users ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ;

ALTER TABLE accounts ADD COLUMN IF NOT EXISTS enforce_mfa BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE accounts ADD COLUMN IF NOT EXISTS region TEXT;
ALTER TABLE accounts ADD COLUMN IF NOT EXISTS plan TEXT NOT NULL DEFAULT 'standard';
ALTER TABLE accounts ADD COLUMN IF NOT EXISTS rate_limit_override INT;

CREATE TABLE IF NOT EXISTS data_export_requests (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    account_id UUID NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    status TEXT NOT NULL DEFAULT 'pending',
    artifact JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_data_export_user ON data_export_requests(user_id);

CREATE TABLE IF NOT EXISTS scim_tokens (
    id UUID PRIMARY KEY,
    account_id UUID NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    revoked BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_scim_tokens_account ON scim_tokens(account_id);

-- Login hot-path covering index
CREATE INDEX IF NOT EXISTS idx_users_email_login ON users (LOWER(email))
    INCLUDE (id, password_hash, mfa_enabled, locked_until, deleted_at);

-- Append-only audit role hint (application uses dedicated DB user in production)
COMMENT ON TABLE audit_events IS 'Append-only: deny UPDATE/DELETE for authsvc_app role in production';
