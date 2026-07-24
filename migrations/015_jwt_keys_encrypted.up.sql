-- Remove plaintext JWT private keys from Postgres; store encrypted blob only.

ALTER TABLE signing_keys ADD COLUMN IF NOT EXISTS encrypted_private_pem TEXT;

-- Legacy rows: move plaintext into encrypted column (re-encrypted on next server boot).
UPDATE signing_keys
SET encrypted_private_pem = private_key_pem
WHERE private_key_pem IS NOT NULL
  AND encrypted_private_pem IS NULL;

ALTER TABLE signing_keys DROP COLUMN IF EXISTS private_key_pem;

COMMENT ON COLUMN signing_keys.encrypted_private_pem IS
    'AES-GCM encrypted private key PEM via DataKeyStore; prefer JWT_PRIVATE_KEY_PEM env in production';
