use authsvc_core::AuthError;
use chrono::Utc;
use sqlx::Row;
use uuid::Uuid;

use super::super::PostgresStore;

impl PostgresStore {
    pub async fn soft_delete_user(&self, user_id: Uuid) -> Result<(), AuthError> {
        sqlx::query("UPDATE users SET deleted_at = $2, updated_at = $2 WHERE id = $1")
            .bind(user_id)
            .bind(Utc::now())
            .execute(self.pool())
            .await
            .map_err(|e| AuthError::Internal(e.to_string()))?;
        Ok(())
    }

    pub async fn anonymize_user(&self, user_id: Uuid) -> Result<(), AuthError> {
        let anon_email = format!("deleted-{user_id}@deleted.authsvc.local");
        sqlx::query(
            "UPDATE users SET email = $2, display_name = NULL, password_hash = NULL,
             email_verified = FALSE, mfa_enabled = FALSE, deleted_at = COALESCE(deleted_at, NOW()),
             updated_at = NOW() WHERE id = $1",
        )
        .bind(user_id)
        .bind(anon_email)
        .execute(self.pool())
        .await
        .map_err(|e| AuthError::Internal(e.to_string()))?;
        Ok(())
    }

    pub async fn create_export_request(
        &self,
        user_id: Uuid,
        account_id: Uuid,
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
        sqlx::query(
            "INSERT INTO data_export_requests (id, user_id, account_id, status) VALUES ($1, $2, $3, 'pending')",
        )
        .bind(id)
        .bind(user_id)
        .bind(account_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| AuthError::Internal(e.to_string()))?;
        tx.commit()
            .await
            .map_err(|e| AuthError::Internal(e.to_string()))?;
        Ok(id)
    }

    pub async fn complete_export_request(
        &self,
        id: Uuid,
        account_id: Uuid,
        artifact: &serde_json::Value,
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
        sqlx::query(
            "UPDATE data_export_requests SET status = 'completed', artifact = $2, completed_at = NOW() WHERE id = $1",
        )
        .bind(id)
        .bind(artifact)
        .execute(&mut *tx)
        .await
        .map_err(|e| AuthError::Internal(e.to_string()))?;
        tx.commit()
            .await
            .map_err(|e| AuthError::Internal(e.to_string()))?;
        Ok(())
    }

    pub async fn list_user_identities(&self, user_id: Uuid) -> Result<Vec<serde_json::Value>, AuthError> {
        let rows = sqlx::query(
            "SELECT provider, provider_subject, email, created_at FROM user_identities WHERE user_id = $1",
        )
        .bind(user_id)
        .fetch_all(self.pool())
        .await
        .map_err(|e| AuthError::Internal(e.to_string()))?;
        Ok(rows
            .into_iter()
            .map(|r| {
                serde_json::json!({
                    "provider": r.get::<String, _>("provider"),
                    "subject": r.get::<String, _>("provider_subject"),
                    "email": r.get::<Option<String>, _>("email"),
                    "created_at": r.get::<chrono::DateTime<chrono::Utc>, _>("created_at"),
                })
            })
            .collect())
    }

    pub async fn list_user_audit_events(
        &self,
        user_id: Uuid,
        limit: i64,
    ) -> Result<Vec<serde_json::Value>, AuthError> {
        let actor = user_id.to_string();
        let rows = sqlx::query(
            "SELECT action, resource, ip_address, metadata, created_at FROM audit_events
             WHERE actor_id = $1 ORDER BY created_at DESC LIMIT $2",
        )
        .bind(actor)
        .bind(limit)
        .fetch_all(self.pool())
        .await
        .map_err(|e| AuthError::Internal(e.to_string()))?;
        Ok(rows
            .into_iter()
            .map(|r| {
                serde_json::json!({
                    "action": r.get::<String, _>("action"),
                    "resource": r.get::<Option<String>, _>("resource"),
                    "ip": r.get::<Option<String>, _>("ip_address"),
                    "metadata": r.get::<serde_json::Value, _>("metadata"),
                    "created_at": r.get::<chrono::DateTime<chrono::Utc>, _>("created_at"),
                })
            })
            .collect())
    }

    pub async fn create_scim_token(
        &self,
        account_id: Uuid,
        name: &str,
        token_hash: &str,
    ) -> Result<Uuid, AuthError> {
        let id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO scim_tokens (id, account_id, name, token_hash) VALUES ($1, $2, $3, $4)",
        )
        .bind(id)
        .bind(account_id)
        .bind(name)
        .bind(token_hash)
        .execute(self.pool())
        .await
        .map_err(|e| AuthError::Internal(e.to_string()))?;
        Ok(id)
    }

    pub async fn find_scim_account_by_token_hash(
        &self,
        token_hash: &str,
    ) -> Result<Option<Uuid>, AuthError> {
        let row = sqlx::query(
            "SELECT account_id FROM scim_tokens WHERE token_hash = $1 AND revoked = FALSE",
        )
        .bind(token_hash)
        .fetch_optional(self.pool())
        .await
        .map_err(|e| AuthError::Internal(e.to_string()))?;
        Ok(row.map(|r| r.get("account_id")))
    }

    pub async fn revoke_scim_token(&self, id: Uuid) -> Result<(), AuthError> {
        sqlx::query("UPDATE scim_tokens SET revoked = TRUE WHERE id = $1")
            .bind(id)
            .execute(self.pool())
            .await
            .map_err(|e| AuthError::Internal(e.to_string()))?;
        Ok(())
    }

    pub async fn purge_expired_otp_codes(&self) -> Result<u64, AuthError> {
        let r1 = sqlx::query("DELETE FROM email_otp_codes WHERE expires_at < NOW()")
            .execute(self.pool())
            .await
            .map_err(|e| AuthError::Internal(e.to_string()))?;
        let r2 = sqlx::query("DELETE FROM phone_otp_codes WHERE expires_at < NOW()")
            .execute(self.pool())
            .await
            .map_err(|e| AuthError::Internal(e.to_string()))?;
        Ok(r1.rows_affected() + r2.rows_affected())
    }

    pub async fn purge_old_refresh_tokens(&self, days: i64) -> Result<u64, AuthError> {
        let result = sqlx::query(
            "DELETE FROM refresh_tokens WHERE revoked = TRUE AND expires_at < NOW() - make_interval(days => $1::integer)",
        )
        .bind(days)
        .execute(self.pool())
        .await
        .map_err(|e| AuthError::Internal(e.to_string()))?;
        Ok(result.rows_affected())
    }

    pub async fn purge_old_audit_events(&self, days: i64) -> Result<u64, AuthError> {
        let account_ids: Vec<Uuid> = sqlx::query_scalar("SELECT id FROM accounts")
            .fetch_all(self.pool())
            .await
            .map_err(|e| AuthError::Internal(e.to_string()))?;
        let mut total = 0u64;
        for account_id in account_ids {
            let mut tx = self
                .privileged_pool()
                .begin()
                .await
                .map_err(|e| AuthError::Internal(e.to_string()))?;
            sqlx::query("SELECT set_config('app.account_id', $1, true)")
                .bind(account_id.to_string())
                .execute(&mut *tx)
                .await
                .map_err(|e| AuthError::Internal(e.to_string()))?;
            let result = sqlx::query(
                "DELETE FROM audit_events
                 WHERE account_id = $1
                   AND created_at < NOW() - make_interval(days => $2::integer)",
            )
            .bind(account_id)
            .bind(days)
            .execute(&mut *tx)
            .await
            .map_err(|e| AuthError::Internal(e.to_string()))?;
            tx.commit()
                .await
                .map_err(|e| AuthError::Internal(e.to_string()))?;
            total += result.rows_affected();
        }
        let null_deleted = sqlx::query(
            "DELETE FROM audit_events
             WHERE account_id IS NULL
               AND created_at < NOW() - make_interval(days => $1::integer)",
        )
        .bind(days)
        .execute(self.privileged_pool())
        .await
        .map_err(|e| AuthError::Internal(e.to_string()))?
        .rows_affected();
        Ok(total + null_deleted)
    }

    pub async fn purge_old_dsar_artifacts(&self, days: i64) -> Result<u64, AuthError> {
        let account_ids: Vec<Uuid> = sqlx::query_scalar("SELECT id FROM accounts")
            .fetch_all(self.pool())
            .await
            .map_err(|e| AuthError::Internal(e.to_string()))?;
        let mut total = 0u64;
        for account_id in account_ids {
            let mut tx = self
                .privileged_pool()
                .begin()
                .await
                .map_err(|e| AuthError::Internal(e.to_string()))?;
            sqlx::query("SELECT set_config('app.account_id', $1, true)")
                .bind(account_id.to_string())
                .execute(&mut *tx)
                .await
                .map_err(|e| AuthError::Internal(e.to_string()))?;
            let result = sqlx::query(
                "DELETE FROM data_export_requests
                 WHERE account_id = $1
                   AND completed_at IS NOT NULL
                   AND completed_at < NOW() - make_interval(days => $2::integer)",
            )
            .bind(account_id)
            .bind(days)
            .execute(&mut *tx)
            .await
            .map_err(|e| AuthError::Internal(e.to_string()))?;
            tx.commit()
                .await
                .map_err(|e| AuthError::Internal(e.to_string()))?;
            total += result.rows_affected();
        }
        Ok(total)
    }

    pub async fn complete_erasure(&self, user_id: Uuid, account_ids: &[Uuid]) -> Result<(), AuthError> {
        for query in [
            "DELETE FROM user_identities WHERE user_id = $1",
            "DELETE FROM user_mfa_secrets WHERE user_id = $1",
            "DELETE FROM webauthn_credentials WHERE user_id = $1",
        ] {
            sqlx::query(query)
                .bind(user_id)
                .execute(self.pool())
                .await
                .map_err(|e| AuthError::Internal(e.to_string()))?;
        }
        for account_id in account_ids {
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
            sqlx::query("DELETE FROM account_members WHERE user_id = $1 AND account_id = $2")
                .bind(user_id)
                .bind(account_id)
                .execute(&mut *tx)
                .await
                .map_err(|e| AuthError::Internal(e.to_string()))?;
            sqlx::query(
                "DELETE FROM data_export_requests WHERE user_id = $1 AND account_id = $2",
            )
            .bind(user_id)
            .bind(account_id)
            .execute(&mut *tx)
            .await
            .map_err(|e| AuthError::Internal(e.to_string()))?;
            tx.commit()
                .await
                .map_err(|e| AuthError::Internal(e.to_string()))?;
        }
        Ok(())
    }
}
