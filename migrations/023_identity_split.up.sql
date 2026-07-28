-- Identity / Credential / Profile split (additive; users table remains compatibility shim)

CREATE TABLE IF NOT EXISTS user_emails (
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    email TEXT NOT NULL,
    verified BOOLEAN NOT NULL DEFAULT FALSE,
    is_primary BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (user_id, email)
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_user_emails_lower ON user_emails (LOWER(email));

CREATE TABLE IF NOT EXISTS user_credentials (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider TEXT NOT NULL,
    identifier TEXT,
    secret_hash TEXT,
    website_id UUID REFERENCES websites(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_user_credentials_global_password
    ON user_credentials (user_id)
    WHERE provider = 'password' AND website_id IS NULL;

CREATE INDEX IF NOT EXISTS idx_user_credentials_user ON user_credentials (user_id);

-- Backfill primary emails
INSERT INTO user_emails (user_id, email, verified, is_primary)
SELECT id, email, email_verified, TRUE
FROM users
WHERE deleted_at IS NULL
ON CONFLICT DO NOTHING;

-- Backfill password credentials
INSERT INTO user_credentials (id, user_id, provider, identifier, secret_hash)
SELECT gen_random_uuid(), id, 'password', email, password_hash
FROM users
WHERE password_hash IS NOT NULL AND deleted_at IS NULL
ON CONFLICT DO NOTHING;

-- Expand per-website profiles
ALTER TABLE user_profiles
    ADD COLUMN IF NOT EXISTS first_name TEXT,
    ADD COLUMN IF NOT EXISTS last_name TEXT;

-- Seed profile names from global display_name where missing
UPDATE user_profiles up
SET first_name = split_part(u.display_name, ' ', 1),
    last_name = NULLIF(trim(substring(u.display_name from position(' ' in u.display_name))), '')
FROM users u
WHERE up.user_id = u.id
  AND up.display_name IS NULL
  AND u.display_name IS NOT NULL
  AND u.display_name <> '';

COMMENT ON TABLE user_emails IS 'Verified contact addresses (global identity)';
COMMENT ON TABLE user_credentials IS 'Authentication factors: password, OIDC, passkey, etc.';
