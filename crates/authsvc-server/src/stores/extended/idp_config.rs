use authsvc_core::AuthError;
use sqlx::Row;
use uuid::Uuid;

use super::super::PostgresStore;

impl PostgresStore {
    pub async fn list_idp_configs(
        &self,
        account_id: Uuid,
    ) -> Result<Vec<(Uuid, String, bool, serde_json::Value)>, AuthError> {
        let mut tx = self
            .pool()
            .begin()
            .await
            .map_err(|e| AuthError::Internal(e.to_string()))?;
        sqlx::query("SELECT set_config('app.account_id', $1, true)")
            .bind(account_id.to_string())
            .execute(&mut *tx)
            .await
            .map_err(|e| AuthError::Internal(e.to_string()))?;
        let rows = sqlx::query(
            "SELECT id, provider, enabled, config_json FROM account_idp_configs WHERE account_id = $1",
        )
        .bind(account_id)
        .fetch_all(&mut *tx)
        .await
        .map_err(|e| AuthError::Internal(e.to_string()))?;
        tx.commit()
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
        let mut tx = self
            .pool()
            .begin()
            .await
            .map_err(|e| AuthError::Internal(e.to_string()))?;
        sqlx::query("SELECT set_config('app.account_id', $1, true)")
            .bind(account_id.to_string())
            .execute(&mut *tx)
            .await
            .map_err(|e| AuthError::Internal(e.to_string()))?;
        let row = sqlx::query(
            "SELECT id, enabled, config_json FROM account_idp_configs WHERE account_id = $1 AND provider = $2",
        )
        .bind(account_id)
        .bind(provider)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| AuthError::Internal(e.to_string()))?;
        tx.commit()
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
        let mut tx = self
            .pool()
            .begin()
            .await
            .map_err(|e| AuthError::Internal(e.to_string()))?;
        sqlx::query("SELECT set_config('app.account_id', $1, true)")
            .bind(account_id.to_string())
            .execute(&mut *tx)
            .await
            .map_err(|e| AuthError::Internal(e.to_string()))?;
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
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| AuthError::Internal(e.to_string()))?;
        tx.commit()
            .await
            .map_err(|e| AuthError::Internal(e.to_string()))?;
        Ok(row.get("id"))
    }

    pub async fn delete_idp_config(
        &self,
        account_id: Uuid,
        provider: &str,
    ) -> Result<(), AuthError> {
        let mut tx = self
            .pool()
            .begin()
            .await
            .map_err(|e| AuthError::Internal(e.to_string()))?;
        sqlx::query("SELECT set_config('app.account_id', $1, true)")
            .bind(account_id.to_string())
            .execute(&mut *tx)
            .await
            .map_err(|e| AuthError::Internal(e.to_string()))?;
        sqlx::query("DELETE FROM account_idp_configs WHERE account_id = $1 AND provider = $2")
            .bind(account_id)
            .bind(provider)
            .execute(&mut *tx)
            .await
            .map_err(|e| AuthError::Internal(e.to_string()))?;
        tx.commit()
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

    pub async fn account_rate_limit_override(
        &self,
        account_id: Uuid,
    ) -> Result<Option<i32>, AuthError> {
        let row = sqlx::query("SELECT rate_limit_override FROM accounts WHERE id = $1")
            .bind(account_id)
            .fetch_optional(self.pool())
            .await
            .map_err(|e| AuthError::Internal(e.to_string()))?;
        Ok(row.and_then(|r| r.get::<Option<i32>, _>("rate_limit_override")))
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
        let mut tx = self
            .pool()
            .begin()
            .await
            .map_err(|e| AuthError::Internal(e.to_string()))?;
        sqlx::query("SELECT set_config('app.account_id', $1, true)")
            .bind(account_id.to_string())
            .execute(&mut *tx)
            .await
            .map_err(|e| AuthError::Internal(e.to_string()))?;
        let rows = sqlx::query(
            "SELECT u.id, u.email, u.display_name, u.status
             FROM users u
             JOIN account_members am ON am.user_id = u.id
             WHERE am.account_id = $1 AND u.deleted_at IS NULL",
        )
        .bind(account_id)
        .fetch_all(&mut *tx)
        .await
        .map_err(|e| AuthError::Internal(e.to_string()))?;
        tx.commit()
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
        let mut tx = self
            .pool()
            .begin()
            .await
            .map_err(|e| AuthError::Internal(e.to_string()))?;
        sqlx::query("SELECT set_config('app.account_id', $1, true)")
            .bind(account_id.to_string())
            .execute(&mut *tx)
            .await
            .map_err(|e| AuthError::Internal(e.to_string()))?;
        let row = sqlx::query(
            "SELECT u.id, u.email, u.display_name, u.status
             FROM users u
             JOIN account_members am ON am.user_id = u.id
             WHERE am.account_id = $1 AND u.id = $2 AND u.deleted_at IS NULL",
        )
        .bind(account_id)
        .bind(user_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| AuthError::Internal(e.to_string()))?;
        tx.commit()
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

    pub async fn scim_user_in_account(
        &self,
        account_id: Uuid,
        user_id: Uuid,
    ) -> Result<bool, AuthError> {
        let mut tx = self
            .pool()
            .begin()
            .await
            .map_err(|e| AuthError::Internal(e.to_string()))?;
        sqlx::query("SELECT set_config('app.account_id', $1, true)")
            .bind(account_id.to_string())
            .execute(&mut *tx)
            .await
            .map_err(|e| AuthError::Internal(e.to_string()))?;
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS(
                SELECT 1 FROM account_members
                WHERE account_id = $1 AND user_id = $2
             )",
        )
        .bind(account_id)
        .bind(user_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| AuthError::Internal(e.to_string()))?;
        tx.commit()
            .await
            .map_err(|e| AuthError::Internal(e.to_string()))?;
        Ok(exists)
    }

    pub async fn update_scim_user_display_name(
        &self,
        account_id: Uuid,
        user_id: Uuid,
        display_name: Option<&str>,
    ) -> Result<(), AuthError> {
        if !self.scim_user_in_account(account_id, user_id).await? {
            return Err(AuthError::UserNotFound);
        }
        sqlx::query(
            "UPDATE users SET display_name = $2, updated_at = NOW() WHERE id = $1 AND deleted_at IS NULL",
        )
        .bind(user_id)
        .bind(display_name)
        .execute(self.pool())
        .await
        .map_err(|e| AuthError::Internal(e.to_string()))?;
        sqlx::query(
            "UPDATE account_members SET display_name = $3 WHERE account_id = $1 AND user_id = $2",
        )
        .bind(account_id)
        .bind(user_id)
        .bind(display_name)
        .execute(self.pool())
        .await
        .map_err(|e| AuthError::Internal(e.to_string()))?;
        Ok(())
    }

    pub async fn set_scim_user_active(
        &self,
        account_id: Uuid,
        user_id: Uuid,
        active: bool,
    ) -> Result<(), AuthError> {
        if !self.scim_user_in_account(account_id, user_id).await? {
            return Err(AuthError::UserNotFound);
        }
        let status = if active { "active" } else { "suspended" };
        sqlx::query("UPDATE users SET status = $2, updated_at = NOW() WHERE id = $1")
            .bind(user_id)
            .bind(status)
            .execute(self.pool())
            .await
            .map_err(|e| AuthError::Internal(e.to_string()))?;
        sqlx::query(
            "UPDATE account_members SET status = $3 WHERE account_id = $1 AND user_id = $2",
        )
        .bind(account_id)
        .bind(user_id)
        .bind(status)
        .execute(self.pool())
        .await
        .map_err(|e| AuthError::Internal(e.to_string()))?;
        Ok(())
    }

    pub async fn get_scim_group(
        &self,
        account_id: Uuid,
        role_id: Uuid,
    ) -> Result<Option<serde_json::Value>, AuthError> {
        let role = sqlx::query(
            "SELECT id, name FROM roles WHERE id = $1 AND account_id = $2",
        )
        .bind(role_id)
        .bind(account_id)
        .fetch_optional(self.pool())
        .await
        .map_err(|e| AuthError::Internal(e.to_string()))?;
        let Some(role) = role else {
            return Ok(None);
        };

        let members = sqlx::query(
            "SELECT ur.user_id
             FROM user_roles ur
             JOIN roles r ON r.id = ur.role_id
             JOIN account_members am ON am.user_id = ur.user_id AND am.account_id = r.account_id
             WHERE ur.role_id = $1 AND r.account_id = $2",
        )
        .bind(role_id)
        .bind(account_id)
        .fetch_all(self.pool())
        .await
        .map_err(|e| AuthError::Internal(e.to_string()))?;

        let member_values: Vec<serde_json::Value> = members
            .into_iter()
            .map(|r| {
                serde_json::json!({
                    "value": r.get::<Uuid, _>("user_id").to_string(),
                })
            })
            .collect();

        Ok(Some(serde_json::json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
            "id": role.get::<Uuid, _>("id"),
            "displayName": role.get::<String, _>("name"),
            "members": member_values,
        })))
    }

    pub async fn add_scim_group_member(
        &self,
        account_id: Uuid,
        role_id: Uuid,
        user_id: Uuid,
    ) -> Result<(), AuthError> {
        let role_exists: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM roles WHERE id = $1 AND account_id = $2)",
        )
        .bind(role_id)
        .bind(account_id)
        .fetch_one(self.pool())
        .await
        .map_err(|e| AuthError::Internal(e.to_string()))?;
        if !role_exists {
            return Err(AuthError::NotFound("group".into()));
        }
        if !self.scim_user_in_account(account_id, user_id).await? {
            return Err(AuthError::UserNotFound);
        }
        sqlx::query(
            "INSERT INTO user_roles (user_id, role_id) VALUES ($1, $2) ON CONFLICT DO NOTHING",
        )
        .bind(user_id)
        .bind(role_id)
        .execute(self.pool())
        .await
        .map_err(|e| AuthError::Internal(e.to_string()))?;
        Ok(())
    }

    pub async fn remove_scim_group_member(
        &self,
        account_id: Uuid,
        role_id: Uuid,
        user_id: Uuid,
    ) -> Result<(), AuthError> {
        let result = sqlx::query(
            "DELETE FROM user_roles ur
             USING roles r
             WHERE ur.role_id = r.id
               AND ur.user_id = $1
               AND ur.role_id = $2
               AND r.account_id = $3",
        )
        .bind(user_id)
        .bind(role_id)
        .bind(account_id)
        .execute(self.pool())
        .await
        .map_err(|e| AuthError::Internal(e.to_string()))?;
        if result.rows_affected() == 0 {
            return Err(AuthError::NotFound("group membership".into()));
        }
        Ok(())
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
