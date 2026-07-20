use authsvc_core::AuthError;
use chrono::{DateTime, Utc};
use sqlx::Row;
use uuid::Uuid;

use super::super::PostgresStore;

impl PostgresStore {
    pub async fn store_email_otp(
        &self,
        email: &str,
        code_hash: &str,
        expires_at: DateTime<Utc>,
    ) -> Result<(), AuthError> {
        sqlx::query(
            "INSERT INTO email_otp_codes (id, email, code_hash, expires_at) VALUES ($1, $2, $3, $4)",
        )
        .bind(Uuid::new_v4())
        .bind(email)
        .bind(code_hash)
        .bind(expires_at)
        .execute(self.pool())
        .await
        .map_err(|e| AuthError::Internal(e.to_string()))?;
        Ok(())
    }

    pub async fn consume_email_otp(&self, email: &str, code_hash: &str) -> Result<bool, AuthError> {
        let row = sqlx::query(
            "SELECT id, expires_at, used FROM email_otp_codes
             WHERE LOWER(email) = LOWER($1) AND code_hash = $2
             ORDER BY created_at DESC LIMIT 1",
        )
        .bind(email)
        .bind(code_hash)
        .fetch_optional(self.pool())
        .await
        .map_err(|e| AuthError::Internal(e.to_string()))?;

        let Some(r) = row else {
            return Ok(false);
        };
        if r.get::<bool, _>("used") || r.get::<DateTime<Utc>, _>("expires_at") < Utc::now() {
            return Ok(false);
        }
        sqlx::query("UPDATE email_otp_codes SET used = TRUE WHERE id = $1")
            .bind(r.get::<Uuid, _>("id"))
            .execute(self.pool())
            .await
            .map_err(|e| AuthError::Internal(e.to_string()))?;
        Ok(true)
    }

    // --- Phone OTP ---
    pub async fn store_phone_otp(
        &self,
        phone: &str,
        code_hash: &str,
        expires_at: DateTime<Utc>,
    ) -> Result<(), AuthError> {
        sqlx::query(
            "INSERT INTO phone_otp_codes (id, phone, code_hash, expires_at) VALUES ($1, $2, $3, $4)",
        )
        .bind(Uuid::new_v4())
        .bind(phone)
        .bind(code_hash)
        .bind(expires_at)
        .execute(self.pool())
        .await
        .map_err(|e| AuthError::Internal(e.to_string()))?;
        Ok(())
    }

    pub async fn consume_phone_otp(&self, phone: &str, code_hash: &str) -> Result<bool, AuthError> {
        let row = sqlx::query(
            "SELECT id, expires_at, used FROM phone_otp_codes
             WHERE phone = $1 AND code_hash = $2
             ORDER BY created_at DESC LIMIT 1",
        )
        .bind(phone)
        .bind(code_hash)
        .fetch_optional(self.pool())
        .await
        .map_err(|e| AuthError::Internal(e.to_string()))?;

        let Some(r) = row else {
            return Ok(false);
        };
        if r.get::<bool, _>("used") || r.get::<DateTime<Utc>, _>("expires_at") < Utc::now() {
            return Ok(false);
        }
        sqlx::query("UPDATE phone_otp_codes SET used = TRUE WHERE id = $1")
            .bind(r.get::<Uuid, _>("id"))
            .execute(self.pool())
            .await
            .map_err(|e| AuthError::Internal(e.to_string()))?;
        Ok(true)
    }

    pub async fn find_user_id_by_phone(&self, phone: &str) -> Result<Option<Uuid>, AuthError> {
        let row = sqlx::query(
            "SELECT user_id FROM user_phones WHERE phone = $1 AND verified = TRUE",
        )
        .bind(phone)
        .fetch_optional(self.pool())
        .await
        .map_err(|e| AuthError::Internal(e.to_string()))?;
        Ok(row.map(|r| r.get("user_id")))
    }

    pub async fn link_verified_phone(&self, user_id: Uuid, phone: &str) -> Result<(), AuthError> {
        sqlx::query(
            "INSERT INTO user_phones (user_id, phone, verified) VALUES ($1, $2, TRUE)
             ON CONFLICT (phone) DO UPDATE SET user_id = $1, verified = TRUE",
        )
        .bind(user_id)
        .bind(phone)
        .execute(self.pool())
        .await
        .map_err(|e| AuthError::Internal(e.to_string()))?;
        Ok(())
    }
}
