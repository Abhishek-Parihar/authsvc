use authsvc_core::AuthError;
use chrono::{DateTime, Utc};
use sqlx::Row;
use uuid::Uuid;

use super::super::PostgresStore;

impl PostgresStore {
    pub async fn create_api_key(
        &self,
        account_id: Uuid,
        name: &str,
        prefix: &str,
        hash: &str,
        scopes: &[String],
        expires_at: Option<DateTime<Utc>>,
    ) -> Result<Uuid, AuthError> {
        let id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO api_keys (id, account_id, name, key_prefix, key_hash, scopes, expires_at) VALUES ($1,$2,$3,$4,$5,$6,$7)",
        )
        .bind(id)
        .bind(account_id)
        .bind(name)
        .bind(prefix)
        .bind(hash)
        .bind(scopes)
        .bind(expires_at)
        .execute(self.pool())
        .await
        .map_err(|e| AuthError::Internal(e.to_string()))?;
        Ok(id)
    }

    pub async fn find_api_key(&self, hash: &str) -> Result<Option<(Uuid, Uuid, Vec<String>)>, AuthError> {
        let row = sqlx::query(
            "SELECT id, account_id, scopes, expires_at, revoked FROM api_keys WHERE key_hash = $1",
        )
        .bind(hash)
        .fetch_optional(self.pool())
        .await
        .map_err(|e| AuthError::Internal(e.to_string()))?;
        let Some(r) = row else {
            return Ok(None);
        };
        if r.get::<bool, _>("revoked") {
            return Ok(None);
        }
        if let Some(exp) = r.get::<Option<DateTime<Utc>>, _>("expires_at") {
            if exp < Utc::now() {
                return Ok(None);
            }
        }
        Ok(Some((r.get("id"), r.get("account_id"), r.get("scopes"))))
    }

    pub async fn revoke_api_key(&self, id: Uuid) -> Result<(), AuthError> {
        sqlx::query("UPDATE api_keys SET revoked = TRUE WHERE id = $1")
            .bind(id)
            .execute(self.pool())
            .await
            .map_err(|e| AuthError::Internal(e.to_string()))?;
        Ok(())
    }

}
