use authsvc_core::AuthError;
use sqlx::Row;
use uuid::Uuid;

use super::super::PostgresStore;

impl PostgresStore {
    pub async fn insert_user_email(
        &self,
        user_id: Uuid,
        email: &str,
        verified: bool,
        is_primary: bool,
    ) -> Result<(), AuthError> {
        sqlx::query(
            "INSERT INTO user_emails (user_id, email, verified, is_primary)
             VALUES ($1, $2, $3, $4)
             ON CONFLICT (user_id, email) DO NOTHING",
        )
        .bind(user_id)
        .bind(email)
        .bind(verified)
        .bind(is_primary)
        .execute(self.pool())
        .await
        .map_err(|e| AuthError::Internal(e.to_string()))?;
        Ok(())
    }

    pub async fn insert_password_credential(
        &self,
        user_id: Uuid,
        email: &str,
        secret_hash: &str,
    ) -> Result<(), AuthError> {
        sqlx::query(
            "INSERT INTO user_credentials (id, user_id, provider, identifier, secret_hash)
             VALUES ($1, $2, 'password', $3, $4)",
        )
        .bind(Uuid::new_v4())
        .bind(user_id)
        .bind(email)
        .bind(secret_hash)
        .execute(self.pool())
        .await
        .map_err(|e| AuthError::Internal(e.to_string()))?;
        Ok(())
    }

    pub async fn find_password_hash(&self, user_id: Uuid) -> Result<Option<String>, AuthError> {
        let row = sqlx::query(
            "SELECT secret_hash FROM user_credentials
             WHERE user_id = $1 AND provider = 'password' AND website_id IS NULL
             LIMIT 1",
        )
        .bind(user_id)
        .fetch_optional(self.pool())
        .await
        .map_err(|e| AuthError::Internal(e.to_string()))?;
        Ok(row.and_then(|r| r.get("secret_hash")))
    }
}
