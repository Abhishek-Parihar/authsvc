-- OAuth 2.0 device authorization grant
CREATE TABLE IF NOT EXISTS device_codes (
    device_code_hash TEXT PRIMARY KEY,
    user_code TEXT NOT NULL UNIQUE,
    client_id UUID NOT NULL REFERENCES oauth_clients(id) ON DELETE CASCADE,
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    scopes TEXT[] NOT NULL DEFAULT '{}',
    approved BOOLEAN NOT NULL DEFAULT FALSE,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_device_codes_user_code ON device_codes (user_code);
CREATE INDEX IF NOT EXISTS idx_device_codes_expires ON device_codes (expires_at);

-- Per-website user profiles (Identity vs Profile split)
CREATE TABLE IF NOT EXISTS user_profiles (
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    website_id UUID NOT NULL REFERENCES websites(id) ON DELETE CASCADE,
    display_name TEXT,
    avatar_url TEXT,
    locale TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (user_id, website_id)
);

CREATE INDEX IF NOT EXISTS idx_user_profiles_website ON user_profiles (website_id);
