ALTER TABLE signing_keys ADD COLUMN IF NOT EXISTS private_key_pem TEXT;
UPDATE signing_keys SET private_key_pem = encrypted_private_pem WHERE encrypted_private_pem IS NOT NULL;
ALTER TABLE signing_keys DROP COLUMN IF EXISTS encrypted_private_pem;
