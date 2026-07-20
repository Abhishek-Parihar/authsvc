use authsvc_core::{AccountOption, AuthError, PortalInfo};
use sqlx::Row;
use uuid::Uuid;

use super::super::PostgresStore;

impl PostgresStore {
    pub async fn find_portal_by_domain(&self, domain: &str) -> Result<Option<PortalInfo>, AuthError> {
        let row = sqlx::query(
            "SELECT w.id AS website_id, w.account_id, w.slug AS website_slug, w.name AS website_name,
                    w.domain, w.portal_name, w.logo_url, w.portal_type,
                    a.slug AS account_slug, a.name AS account_name
             FROM websites w
             JOIN accounts a ON a.id = w.account_id
             WHERE LOWER(w.domain) = LOWER($1)
                OR LOWER(COALESCE(w.custom_domain, '')) = LOWER($1)
             LIMIT 1",
        )
        .bind(domain)
        .fetch_optional(self.pool())
        .await
        .map_err(|e| AuthError::Internal(e.to_string()))?;

        Ok(row.map(|r| PortalInfo {
            account_id: r.get("account_id"),
            account_slug: r.get("account_slug"),
            account_name: r.get("account_name"),
            website_id: r.get("website_id"),
            website_slug: r.get("website_slug"),
            website_name: r.get("website_name"),
            domain: r.get("domain"),
            portal_name: r.get("portal_name"),
            logo_url: r.get("logo_url"),
            portal_type: r.get("portal_type"),
        }))
    }

    pub async fn list_user_account_options(
        &self,
        user_id: Uuid,
    ) -> Result<Vec<AccountOption>, AuthError> {
        let rows = sqlx::query(
            "SELECT a.id AS account_id, a.slug, a.name, am.status
             FROM account_members am
             JOIN accounts a ON a.id = am.account_id
             WHERE am.user_id = $1
             ORDER BY a.name",
        )
        .bind(user_id)
        .fetch_all(self.pool())
        .await
        .map_err(|e| AuthError::Internal(e.to_string()))?;

        Ok(rows
            .into_iter()
            .map(|r| AccountOption {
                account_id: r.get("account_id"),
                slug: r.get("slug"),
                name: r.get("name"),
                status: r.get("status"),
            })
            .collect())
    }

}
