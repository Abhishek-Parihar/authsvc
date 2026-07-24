use authsvc_core::AuthError;
use chrono::{DateTime, Utc};
use sqlx::Row;
use uuid::Uuid;

use super::super::PostgresStore;

impl PostgresStore {
    pub async fn store_mfa_secret(
        &self,
        user_id: Uuid,
        encrypted: &str,
        recovery_hashes: &[String],
        enable: bool,
    ) -> Result<(), AuthError> {
        sqlx::query(
            "INSERT INTO user_mfa_secrets (user_id, encrypted_secret, recovery_codes_hash)
             VALUES ($1,$2,$3) ON CONFLICT (user_id) DO UPDATE SET encrypted_secret = $2, recovery_codes_hash = $3",
        )
        .bind(user_id)
        .bind(encrypted)
        .bind(recovery_hashes)
        .execute(self.pool())
        .await
        .map_err(|e| AuthError::Internal(e.to_string()))?;
        if enable {
            sqlx::query("UPDATE users SET mfa_enabled = TRUE WHERE id = $1")
                .bind(user_id)
                .execute(self.pool())
                .await
                .map_err(|e| AuthError::Internal(e.to_string()))?;
        }
        Ok(())
    }

    pub async fn enable_mfa(&self, user_id: Uuid) -> Result<(), AuthError> {
        sqlx::query("UPDATE users SET mfa_enabled = TRUE WHERE id = $1")
            .bind(user_id)
            .execute(self.pool())
            .await
            .map_err(|e| AuthError::Internal(e.to_string()))?;
        Ok(())
    }

    pub async fn consume_recovery_code(
        &self,
        user_id: Uuid,
        code_hash: &str,
    ) -> Result<bool, AuthError> {
        let row = sqlx::query(
            "SELECT recovery_codes_hash FROM user_mfa_secrets WHERE user_id = $1",
        )
        .bind(user_id)
        .fetch_optional(self.pool())
        .await
        .map_err(|e| AuthError::Internal(e.to_string()))?;
        let Some(r) = row else {
            return Ok(false);
        };
        let hashes: Vec<String> = r.get("recovery_codes_hash");
        if !hashes.iter().any(|h| h == code_hash) {
            return Ok(false);
        }
        let remaining: Vec<String> = hashes.into_iter().filter(|h| h != code_hash).collect();
        sqlx::query(
            "UPDATE user_mfa_secrets SET recovery_codes_hash = $2 WHERE user_id = $1",
        )
        .bind(user_id)
        .bind(&remaining)
        .execute(self.pool())
        .await
        .map_err(|e| AuthError::Internal(e.to_string()))?;
        Ok(true)
    }

    pub async fn get_mfa_secret(&self, user_id: Uuid) -> Result<Option<String>, AuthError> {
        let row = sqlx::query("SELECT encrypted_secret FROM user_mfa_secrets WHERE user_id = $1")
            .bind(user_id)
            .fetch_optional(self.pool())
            .await
            .map_err(|e| AuthError::Internal(e.to_string()))?;
        Ok(row.map(|r| r.get("encrypted_secret")))
    }

    pub async fn store_mfa_challenge(&self, id: Uuid, user_id: Uuid, client_id: Uuid, expires: DateTime<Utc>) -> Result<(), AuthError> {
        sqlx::query(
            "INSERT INTO mfa_challenges (challenge_id, user_id, client_id, expires_at) VALUES ($1,$2,$3,$4)",
        )
        .bind(id)
        .bind(user_id)
        .bind(client_id)
        .bind(expires)
        .execute(self.pool())
        .await
        .map_err(|e| AuthError::Internal(e.to_string()))?;
        Ok(())
    }

    pub async fn complete_mfa_challenge(&self, id: Uuid) -> Result<Option<(Uuid, Uuid)>, AuthError> {
        let row = sqlx::query(
            "SELECT user_id, client_id, expires_at, completed FROM mfa_challenges WHERE challenge_id = $1",
        )
        .bind(id)
        .fetch_optional(self.pool())
        .await
        .map_err(|e| AuthError::Internal(e.to_string()))?;
        let Some(r) = row else {
            return Ok(None);
        };
        if r.get::<bool, _>("completed") || r.get::<DateTime<Utc>, _>("expires_at") < Utc::now() {
            return Ok(None);
        }
        sqlx::query("UPDATE mfa_challenges SET completed = TRUE WHERE challenge_id = $1")
            .bind(id)
            .execute(self.pool())
            .await
            .map_err(|e| AuthError::Internal(e.to_string()))?;
        Ok(Some((r.get("user_id"), r.get("client_id"))))
    }

    pub async fn disable_mfa(&self, user_id: Uuid) -> Result<(), AuthError> {
        sqlx::query("DELETE FROM user_mfa_secrets WHERE user_id = $1")
            .bind(user_id)
            .execute(self.pool())
            .await
            .map_err(|e| AuthError::Internal(e.to_string()))?;
        sqlx::query("UPDATE users SET mfa_enabled = FALSE WHERE id = $1")
            .bind(user_id)
            .execute(self.pool())
            .await
            .map_err(|e| AuthError::Internal(e.to_string()))?;
        Ok(())
    }

}
