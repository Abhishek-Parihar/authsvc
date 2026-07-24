-- SAML 2.0 Identity Provider: registered service providers (relying parties)
CREATE TABLE IF NOT EXISTS saml_service_providers (
    id UUID PRIMARY KEY,
    account_id UUID NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    entity_id TEXT NOT NULL,
    acs_url TEXT NOT NULL,
    slo_url TEXT,
    sp_cert_pem TEXT,
    want_authn_requests_signed BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (account_id, entity_id)
);

CREATE INDEX IF NOT EXISTS idx_saml_sp_account ON saml_service_providers(account_id);

-- Pending AuthnRequest state between SSO redirect and user login
CREATE TABLE IF NOT EXISTS saml_pending_authn (
    id UUID PRIMARY KEY,
    account_id UUID NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    sp_id UUID NOT NULL REFERENCES saml_service_providers(id) ON DELETE CASCADE,
    request_id TEXT NOT NULL,
    relay_state TEXT,
    acs_url TEXT NOT NULL,
    sp_entity_id TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_saml_pending_expires ON saml_pending_authn(expires_at);
