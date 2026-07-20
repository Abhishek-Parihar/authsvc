ALTER TABLE websites ADD COLUMN IF NOT EXISTS custom_domain TEXT;
CREATE UNIQUE INDEX IF NOT EXISTS idx_websites_custom_domain ON websites (LOWER(custom_domain)) WHERE custom_domain IS NOT NULL;
