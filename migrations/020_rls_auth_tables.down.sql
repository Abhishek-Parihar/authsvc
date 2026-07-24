ALTER TABLE api_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE api_keys FORCE ROW LEVEL SECURITY;
CREATE POLICY api_keys_tenant ON api_keys
    USING (account_id::text = current_setting('app.account_id', true));

ALTER TABLE scim_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE scim_tokens FORCE ROW LEVEL SECURITY;
CREATE POLICY scim_tokens_tenant ON scim_tokens
    USING (account_id::text = current_setting('app.account_id', true));
