-- api_keys and scim_tokens require global hash lookup during authentication.
DROP POLICY IF EXISTS api_keys_tenant ON api_keys;
ALTER TABLE api_keys NO FORCE ROW LEVEL SECURITY;
ALTER TABLE api_keys DISABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS scim_tokens_tenant ON scim_tokens;
ALTER TABLE scim_tokens NO FORCE ROW LEVEL SECURITY;
ALTER TABLE scim_tokens DISABLE ROW LEVEL SECURITY;
