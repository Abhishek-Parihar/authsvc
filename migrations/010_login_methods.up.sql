-- Portal branding on websites
ALTER TABLE websites ADD COLUMN IF NOT EXISTS portal_name TEXT;
ALTER TABLE websites ADD COLUMN IF NOT EXISTS logo_url TEXT;
ALTER TABLE websites ADD COLUMN IF NOT EXISTS portal_type TEXT NOT NULL DEFAULT 'web';

-- Email OTP (numeric code, distinct from magic link)
CREATE TABLE IF NOT EXISTS email_otp_codes (
    id UUID PRIMARY KEY,
    email TEXT NOT NULL,
    code_hash TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    used BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_email_otp_email ON email_otp_codes (LOWER(email));

-- Phone identity + OTP
CREATE TABLE IF NOT EXISTS user_phones (
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    phone TEXT NOT NULL,
    verified BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (user_id, phone),
    UNIQUE (phone)
);

CREATE TABLE IF NOT EXISTS phone_otp_codes (
    id UUID PRIMARY KEY,
    phone TEXT NOT NULL,
    code_hash TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    used BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_phone_otp_phone ON phone_otp_codes (phone);

CREATE INDEX IF NOT EXISTS idx_websites_domain ON websites (LOWER(domain)) WHERE domain IS NOT NULL;
