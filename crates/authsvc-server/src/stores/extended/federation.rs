use authsvc_core::AuthError;
use chrono::{DateTime, Utc};
use sqlx::Row;
use uuid::Uuid;

use super::super::PostgresStore;

impl PostgresStore {
    pub async fn link_identity(
        &self,
        user_id: Uuid,
        provider: &str,
        subject: &str,
        email: Option<&str>,
    ) -> Result<(), AuthError> {
        sqlx::query(
            "INSERT INTO user_identities (id, user_id, provider, provider_subject, email)
             VALUES ($1,$2,$3,$4,$5) ON CONFLICT (provider, provider_subject) DO NOTHING",
        )
        .bind(Uuid::new_v4())
        .bind(user_id)
        .bind(provider)
        .bind(subject)
        .bind(email)
        .execute(self.pool())
        .await
        .map_err(|e| AuthError::Internal(e.to_string()))?;
        Ok(())
    }

    pub async fn find_identity(&self, provider: &str, subject: &str) -> Result<Option<Uuid>, AuthError> {
        let row = sqlx::query("SELECT user_id FROM user_identities WHERE provider = $1 AND provider_subject = $2")
            .bind(provider)
            .bind(subject)
            .fetch_optional(self.pool())
            .await
            .map_err(|e| AuthError::Internal(e.to_string()))?;
        Ok(row.map(|r| r.get("user_id")))
    }

    pub async fn store_federation_state(&self, state: &str, account_id: Uuid, provider: &str, expires: DateTime<Utc>) -> Result<(), AuthError> {
        sqlx::query(
            "INSERT INTO federation_states (state, account_id, provider, expires_at) VALUES ($1,$2,$3,$4)",
        )
        .bind(state)
        .bind(account_id)
        .bind(provider)
        .bind(expires)
        .execute(self.pool())
        .await
        .map_err(|e| AuthError::Internal(e.to_string()))?;
        Ok(())
    }

    pub async fn consume_federation_state(&self, state: &str) -> Result<Option<(Uuid, String)>, AuthError> {
        let row = sqlx::query("SELECT account_id, provider, expires_at FROM federation_states WHERE state = $1")
            .bind(state)
            .fetch_optional(self.pool())
            .await
            .map_err(|e| AuthError::Internal(e.to_string()))?;
        let Some(r) = row else {
            return Ok(None);
        };
        if r.get::<DateTime<Utc>, _>("expires_at") < Utc::now() {
            return Ok(None);
        }
        sqlx::query("DELETE FROM federation_states WHERE state = $1")
            .bind(state)
            .execute(self.pool())
            .await
            .map_err(|e| AuthError::Internal(e.to_string()))?;
        Ok(Some((r.get("account_id"), r.get("provider"))))
    }

}
