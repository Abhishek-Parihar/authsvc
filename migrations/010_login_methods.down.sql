DROP INDEX IF EXISTS idx_websites_domain;
DROP TABLE IF EXISTS phone_otp_codes;
DROP TABLE IF EXISTS user_phones;
DROP TABLE IF EXISTS email_otp_codes;
ALTER TABLE websites DROP COLUMN IF EXISTS portal_type;
ALTER TABLE websites DROP COLUMN IF EXISTS logo_url;
ALTER TABLE websites DROP COLUMN IF EXISTS portal_name;
