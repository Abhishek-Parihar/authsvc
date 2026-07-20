DROP INDEX IF EXISTS idx_websites_custom_domain;
ALTER TABLE websites DROP COLUMN IF EXISTS custom_domain;
