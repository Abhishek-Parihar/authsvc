use authsvc_core::AuthError;
use chrono::{DateTime, Utc};
use sqlx::Row;

use super::super::PostgresStore;

impl PostgresStore {
    pub async fn store_magic_link(&self, hash: &str, email: &str, expires: DateTime<Utc>) -> Result<(), AuthError> {
        sqlx::query(
            "INSERT INTO magic_link_tokens (token_hash, email, expires_at) VALUES ($1,$2,$3)",
        )
        .bind(hash)
        .bind(email)
        .bind(expires)
        .execute(self.pool())
        .await
        .map_err(|e| AuthError::Internal(e.to_string()))?;
        Ok(())
    }

    pub async fn consume_magic_link(&self, hash: &str) -> Result<Option<String>, AuthError> {
        let row = sqlx::query(
            "SELECT email, expires_at, used FROM magic_link_tokens WHERE token_hash = $1",
        )
        .bind(hash)
        .fetch_optional(self.pool())
        .await
        .map_err(|e| AuthError::Internal(e.to_string()))?;
        let Some(r) = row else {
            return Ok(None);
        };
        if r.get::<bool, _>("used") || r.get::<DateTime<Utc>, _>("expires_at") < Utc::now() {
            return Ok(None);
        }
        sqlx::query("UPDATE magic_link_tokens SET used = TRUE WHERE token_hash = $1")
            .bind(hash)
            .execute(self.pool())
            .await
            .map_err(|e| AuthError::Internal(e.to_string()))?;
        Ok(Some(r.get("email")))
    }

}
