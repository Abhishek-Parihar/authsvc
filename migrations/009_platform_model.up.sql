-- Platform model: accounts, websites, memberships (replaces flat tenant scoping)

CREATE TABLE IF NOT EXISTS accounts (
    id UUID PRIMARY KEY,
    slug TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS websites (
    id UUID PRIMARY KEY,
    account_id UUID NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    slug TEXT NOT NULL,
    name TEXT NOT NULL,
    domain TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (account_id, slug)
);

-- Drop all foreign keys to tenants before restructuring columns
ALTER TABLE users DROP CONSTRAINT IF EXISTS users_tenant_id_fkey;
ALTER TABLE oauth_clients DROP CONSTRAINT IF EXISTS oauth_clients_tenant_id_fkey;
ALTER TABLE roles DROP CONSTRAINT IF EXISTS roles_tenant_id_fkey;
ALTER TABLE permissions DROP CONSTRAINT IF EXISTS permissions_tenant_id_fkey;
ALTER TABLE refresh_tokens DROP CONSTRAINT IF EXISTS refresh_tokens_tenant_id_fkey;
ALTER TABLE magic_link_tokens DROP CONSTRAINT IF EXISTS magic_link_tokens_tenant_id_fkey;
ALTER TABLE user_identities DROP CONSTRAINT IF EXISTS user_identities_tenant_id_fkey;
ALTER TABLE tenant_idp_configs DROP CONSTRAINT IF EXISTS tenant_idp_configs_tenant_id_fkey;
ALTER TABLE federation_states DROP CONSTRAINT IF EXISTS federation_states_tenant_id_fkey;
ALTER TABLE api_keys DROP CONSTRAINT IF EXISTS api_keys_tenant_id_fkey;
ALTER TABLE audit_events DROP CONSTRAINT IF EXISTS audit_events_tenant_id_fkey;
ALTER TABLE webhooks DROP CONSTRAINT IF EXISTS webhooks_tenant_id_fkey;
ALTER TABLE casbin_rules DROP CONSTRAINT IF EXISTS casbin_rules_tenant_id_fkey;

CREATE TABLE IF NOT EXISTS account_members (
    account_id UUID NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id UUID REFERENCES roles(id) ON DELETE SET NULL,
    display_name TEXT,
    status TEXT NOT NULL DEFAULT 'active',
    joined_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (account_id, user_id)
);

CREATE TABLE IF NOT EXISTS website_members (
    website_id UUID NOT NULL REFERENCES websites(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id UUID REFERENCES roles(id) ON DELETE SET NULL,
    status TEXT NOT NULL DEFAULT 'active',
    joined_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (website_id, user_id)
);

-- Migrate tenants -> accounts
INSERT INTO accounts (id, slug, name, created_at)
SELECT id, slug, name, created_at FROM tenants
ON CONFLICT (id) DO NOTHING;

-- Default website per account
INSERT INTO websites (id, account_id, slug, name, created_at)
SELECT gen_random_uuid(), t.id, 'default', t.name || ' App', t.created_at
FROM tenants t
ON CONFLICT DO NOTHING;

-- Account membership from existing users
INSERT INTO account_members (account_id, user_id, status, joined_at)
SELECT u.tenant_id, u.id, 'active', u.created_at
FROM users u
ON CONFLICT DO NOTHING;

-- oauth_clients: attach to website
ALTER TABLE oauth_clients ADD COLUMN IF NOT EXISTS website_id UUID REFERENCES websites(id);
ALTER TABLE oauth_clients ADD COLUMN IF NOT EXISTS client_type TEXT NOT NULL DEFAULT 'web';

UPDATE oauth_clients oc
SET website_id = w.id
FROM websites w
WHERE w.account_id = oc.tenant_id AND w.slug = 'default' AND oc.website_id IS NULL;

ALTER TABLE oauth_clients ALTER COLUMN website_id SET NOT NULL;
ALTER TABLE oauth_clients DROP COLUMN IF EXISTS tenant_id;

-- roles: account-scoped
ALTER TABLE roles ADD COLUMN IF NOT EXISTS account_id UUID REFERENCES accounts(id);
ALTER TABLE roles ADD COLUMN IF NOT EXISTS website_id UUID REFERENCES websites(id);
ALTER TABLE roles ADD COLUMN IF NOT EXISTS scope TEXT NOT NULL DEFAULT 'account';

UPDATE roles SET account_id = tenant_id WHERE account_id IS NULL;

ALTER TABLE roles ALTER COLUMN account_id SET NOT NULL;
ALTER TABLE roles DROP CONSTRAINT IF EXISTS roles_tenant_id_name_key;
ALTER TABLE roles DROP COLUMN IF EXISTS tenant_id;
ALTER TABLE roles ADD CONSTRAINT roles_account_id_name_key UNIQUE (account_id, name);

-- permissions: global catalog
ALTER TABLE permissions DROP CONSTRAINT IF EXISTS permissions_tenant_id_resource_action_key;
ALTER TABLE permissions DROP COLUMN IF EXISTS tenant_id;
ALTER TABLE permissions ADD CONSTRAINT permissions_resource_action_key UNIQUE (resource, action);

-- users: global identity
ALTER TABLE users ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'active';
ALTER TABLE users DROP CONSTRAINT IF EXISTS users_tenant_id_email_key;
ALTER TABLE users DROP COLUMN IF EXISTS tenant_id;
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email_lower ON users (LOWER(email));
DROP INDEX IF EXISTS idx_users_tenant_email;

-- refresh tokens
ALTER TABLE refresh_tokens RENAME COLUMN tenant_id TO account_id;

-- magic links: no tenant scope
ALTER TABLE magic_link_tokens DROP COLUMN IF EXISTS tenant_id;

-- federation
ALTER TABLE user_identities DROP COLUMN IF EXISTS tenant_id;

ALTER TABLE tenant_idp_configs RENAME TO account_idp_configs;
ALTER TABLE account_idp_configs RENAME COLUMN tenant_id TO account_id;
ALTER TABLE account_idp_configs DROP CONSTRAINT IF EXISTS tenant_idp_configs_tenant_id_provider_key;
ALTER TABLE account_idp_configs ADD CONSTRAINT account_idp_configs_account_id_provider_key UNIQUE (account_id, provider);

ALTER TABLE federation_states RENAME COLUMN tenant_id TO account_id;

-- api keys
ALTER TABLE api_keys RENAME COLUMN tenant_id TO account_id;

-- audit & webhooks
ALTER TABLE audit_events RENAME COLUMN tenant_id TO account_id;
ALTER TABLE webhooks RENAME COLUMN tenant_id TO account_id;

-- casbin
ALTER TABLE casbin_rules RENAME COLUMN tenant_id TO account_id;
DROP INDEX IF EXISTS idx_casbin_rules_tenant;
CREATE INDEX IF NOT EXISTS idx_casbin_rules_account ON casbin_rules(account_id);

-- Assign admin role on account_members from user_roles
UPDATE account_members am
SET role_id = ur.role_id
FROM user_roles ur
JOIN roles r ON r.id = ur.role_id AND r.name = 'admin'
WHERE am.user_id = ur.user_id AND am.account_id = r.account_id AND am.role_id IS NULL;

-- Add foreign keys to accounts
ALTER TABLE refresh_tokens
    ADD CONSTRAINT refresh_tokens_account_id_fkey
    FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE CASCADE;

ALTER TABLE api_keys
    ADD CONSTRAINT api_keys_account_id_fkey
    FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE CASCADE;

ALTER TABLE audit_events
    ADD CONSTRAINT audit_events_account_id_fkey
    FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE SET NULL;

ALTER TABLE webhooks
    ADD CONSTRAINT webhooks_account_id_fkey
    FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE CASCADE;

ALTER TABLE casbin_rules
    ADD CONSTRAINT casbin_rules_account_id_fkey
    FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE CASCADE;

ALTER TABLE federation_states
    ADD CONSTRAINT federation_states_account_id_fkey
    FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE CASCADE;

ALTER TABLE account_idp_configs
    ADD CONSTRAINT account_idp_configs_account_id_fkey
    FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE CASCADE;

DROP TABLE IF EXISTS tenants;

CREATE INDEX IF NOT EXISTS idx_websites_account ON websites(account_id);
CREATE INDEX IF NOT EXISTS idx_account_members_user ON account_members(user_id);
CREATE INDEX IF NOT EXISTS idx_website_members_user ON website_members(user_id);
CREATE INDEX IF NOT EXISTS idx_oauth_clients_website ON oauth_clients(website_id);
