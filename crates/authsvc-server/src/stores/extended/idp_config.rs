use authsvc_core::AuthError;
use sqlx::Row;
use uuid::Uuid;

use super::super::PostgresStore;

impl PostgresStore {
    pub async fn list_idp_configs(
        &self,
        account_id: Uuid,
    ) -> Result<Vec<(Uuid, String, bool, serde_json::Value)>, AuthError> {
        let rows = sqlx::query(
            "SELECT id, provider, enabled, config_json FROM account_idp_configs WHERE account_id = $1",
        )
        .bind(account_id)
        .fetch_all(self.pool())
        .await
        .map_err(|e| AuthError::Internal(e.to_string()))?;
        Ok(rows
            .into_iter()
            .map(|r| {
                (
                    r.get("id"),
                    r.get("provider"),
                    r.get("enabled"),
                    r.get("config_json"),
                )
            })
            .collect())
    }

    pub async fn get_idp_config(
        &self,
        account_id: Uuid,
        provider: &str,
    ) -> Result<Option<(Uuid, bool, serde_json::Value)>, AuthError> {
        let row = sqlx::query(
            "SELECT id, enabled, config_json FROM account_idp_configs WHERE account_id = $1 AND provider = $2",
        )
        .bind(account_id)
        .bind(provider)
        .fetch_optional(self.pool())
        .await
        .map_err(|e| AuthError::Internal(e.to_string()))?;
        Ok(row.map(|r| (r.get("id"), r.get("enabled"), r.get("config_json"))))
    }

    pub async fn upsert_idp_config(
        &self,
        account_id: Uuid,
        provider: &str,
        enabled: bool,
        config: serde_json::Value,
    ) -> Result<Uuid, AuthError> {
        let id = Uuid::new_v4();
        let row = sqlx::query(
            "INSERT INTO account_idp_configs (id, account_id, provider, enabled, config_json)
             VALUES ($1, $2, $3, $4, $5)
             ON CONFLICT (account_id, provider) DO UPDATE SET enabled = $4, config_json = $5
             RETURNING id",
        )
        .bind(id)
        .bind(account_id)
        .bind(provider)
        .bind(enabled)
        .bind(config)
        .fetch_one(self.pool())
        .await
        .map_err(|e| AuthError::Internal(e.to_string()))?;
        Ok(row.get("id"))
    }

    pub async fn delete_idp_config(
        &self,
        account_id: Uuid,
        provider: &str,
    ) -> Result<(), AuthError> {
        sqlx::query("DELETE FROM account_idp_configs WHERE account_id = $1 AND provider = $2")
            .bind(account_id)
            .bind(provider)
            .execute(self.pool())
            .await
            .map_err(|e| AuthError::Internal(e.to_string()))?;
        Ok(())
    }

    pub async fn account_enforce_mfa(&self, account_id: Uuid) -> Result<bool, AuthError> {
        let row = sqlx::query("SELECT enforce_mfa FROM accounts WHERE id = $1")
            .bind(account_id)
            .fetch_optional(self.pool())
            .await
            .map_err(|e| AuthError::Internal(e.to_string()))?;
        Ok(row.map(|r| r.get::<bool, _>("enforce_mfa")).unwrap_or(false))
    }

    pub async fn account_region(&self, account_id: Uuid) -> Result<Option<String>, AuthError> {
        let row = sqlx::query("SELECT region FROM accounts WHERE id = $1")
            .bind(account_id)
            .fetch_optional(self.pool())
            .await
            .map_err(|e| AuthError::Internal(e.to_string()))?;
        Ok(row.and_then(|r| r.get::<Option<String>, _>("region")))
    }

    pub async fn revoke_user_refresh_tokens(&self, user_id: Uuid) -> Result<(), AuthError> {
        sqlx::query("UPDATE refresh_tokens SET revoked = TRUE WHERE user_id = $1")
            .bind(user_id)
            .execute(self.pool())
            .await
            .map_err(|e| AuthError::Internal(e.to_string()))?;
        Ok(())
    }

    pub async fn list_scim_users(&self, account_id: Uuid) -> Result<Vec<serde_json::Value>, AuthError> {
        let rows = sqlx::query(
            "SELECT u.id, u.email, u.display_name, u.status
             FROM users u
             JOIN account_members am ON am.user_id = u.id
             WHERE am.account_id = $1 AND u.deleted_at IS NULL",
        )
        .bind(account_id)
        .fetch_all(self.pool())
        .await
        .map_err(|e| AuthError::Internal(e.to_string()))?;
        Ok(rows
            .into_iter()
            .map(|r| {
                serde_json::json!({
                    "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
                    "id": r.get::<Uuid, _>("id"),
                    "userName": r.get::<String, _>("email"),
                    "displayName": r.get::<Option<String>, _>("display_name"),
                    "active": r.get::<String, _>("status") == "active",
                })
            })
            .collect())
    }

    pub async fn get_scim_user(
        &self,
        account_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<serde_json::Value>, AuthError> {
        let row = sqlx::query(
            "SELECT u.id, u.email, u.display_name, u.status
             FROM users u
             JOIN account_members am ON am.user_id = u.id
             WHERE am.account_id = $1 AND u.id = $2 AND u.deleted_at IS NULL",
        )
        .bind(account_id)
        .bind(user_id)
        .fetch_optional(self.pool())
        .await
        .map_err(|e| AuthError::Internal(e.to_string()))?;

        Ok(row.map(|r| {
            serde_json::json!({
                "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
                "id": r.get::<Uuid, _>("id"),
                "userName": r.get::<String, _>("email"),
                "displayName": r.get::<Option<String>, _>("display_name"),
                "active": r.get::<String, _>("status") == "active",
            })
        }))
    }

    pub async fn set_account_context(&self, account_id: Uuid) -> Result<(), AuthError> {
        sqlx::query("SELECT set_config('app.account_id', $1, true)")
            .bind(account_id.to_string())
            .execute(self.pool())
            .await
            .map_err(|e| AuthError::Internal(e.to_string()))?;
        Ok(())
    }
}
