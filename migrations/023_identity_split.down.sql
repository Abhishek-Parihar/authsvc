ALTER TABLE user_profiles DROP COLUMN IF EXISTS last_name;
ALTER TABLE user_profiles DROP COLUMN IF EXISTS first_name;
DROP TABLE IF EXISTS user_credentials;
DROP TABLE IF EXISTS user_emails;
