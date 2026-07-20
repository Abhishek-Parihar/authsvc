DROP INDEX IF EXISTS idx_users_email_login;
DROP TABLE IF EXISTS scim_tokens;
DROP TABLE IF EXISTS data_export_requests;
ALTER TABLE accounts DROP COLUMN IF EXISTS rate_limit_override;
ALTER TABLE accounts DROP COLUMN IF EXISTS plan;
ALTER TABLE accounts DROP COLUMN IF EXISTS region;
ALTER TABLE accounts DROP COLUMN IF EXISTS enforce_mfa;
ALTER TABLE users DROP COLUMN IF EXISTS deleted_at;
