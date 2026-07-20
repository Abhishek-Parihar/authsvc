-- Reverting platform model is destructive; restore tenants table skeleton only.

CREATE TABLE IF NOT EXISTS tenants (
    id UUID PRIMARY KEY,
    slug TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO tenants (id, slug, name, created_at)
SELECT id, slug, name, created_at FROM accounts
ON CONFLICT DO NOTHING;

ALTER TABLE users ADD COLUMN IF NOT EXISTS tenant_id UUID REFERENCES tenants(id);
UPDATE users u SET tenant_id = am.account_id
FROM account_members am WHERE am.user_id = u.id;

ALTER TABLE oauth_clients ADD COLUMN IF NOT EXISTS tenant_id UUID REFERENCES tenants(id);
UPDATE oauth_clients oc SET tenant_id = w.account_id
FROM websites w WHERE w.id = oc.website_id;

DROP TABLE IF EXISTS website_members;
DROP TABLE IF EXISTS account_members;
DROP TABLE IF EXISTS websites;
DROP TABLE IF EXISTS accounts;
