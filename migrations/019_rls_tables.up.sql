-- Expand RLS to additional tenant-scoped tables.

ALTER TABLE api_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE api_keys FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS api_keys_tenant ON api_keys;
CREATE POLICY api_keys_tenant ON api_keys
    USING (account_id::text = current_setting('app.account_id', true));

ALTER TABLE webhooks ENABLE ROW LEVEL SECURITY;
ALTER TABLE webhooks FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS webhooks_tenant ON webhooks;
CREATE POLICY webhooks_tenant ON webhooks
    USING (account_id::text = current_setting('app.account_id', true));

ALTER TABLE scim_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE scim_tokens FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS scim_tokens_tenant ON scim_tokens;
CREATE POLICY scim_tokens_tenant ON scim_tokens
    USING (account_id::text = current_setting('app.account_id', true));

ALTER TABLE data_export_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE data_export_requests FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS data_export_requests_tenant ON data_export_requests;
CREATE POLICY data_export_requests_tenant ON data_export_requests
    USING (account_id::text = current_setting('app.account_id', true));

ALTER TABLE account_idp_configs ENABLE ROW LEVEL SECURITY;
ALTER TABLE account_idp_configs FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS account_idp_configs_tenant ON account_idp_configs;
CREATE POLICY account_idp_configs_tenant ON account_idp_configs
    USING (account_id::text = current_setting('app.account_id', true));
