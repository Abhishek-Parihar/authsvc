use authsvc_core::AuthError;
use chrono::{DateTime, Utc};
use sqlx::Row;
use uuid::Uuid;

use super::super::PostgresStore;

pub struct DeviceCodeRecord {
    pub client_id: Uuid,
    pub user_id: Option<Uuid>,
    pub scopes: Vec<String>,
    pub approved: bool,
    pub expires_at: DateTime<Utc>,
}

impl PostgresStore {
    pub async fn store_device_code(
        &self,
        device_code_hash: &str,
        user_code: &str,
        client_id: Uuid,
        scopes: &[String],
        expires_at: DateTime<Utc>,
    ) -> Result<(), AuthError> {
        sqlx::query(
            "INSERT INTO device_codes (device_code_hash, user_code, client_id, scopes, expires_at)
             VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(device_code_hash)
        .bind(user_code)
        .bind(client_id)
        .bind(scopes)
        .bind(expires_at)
        .execute(self.pool())
        .await
        .map_err(|e| AuthError::Internal(e.to_string()))?;
        Ok(())
    }

    pub async fn get_device_code(
        &self,
        device_code_hash: &str,
    ) -> Result<Option<DeviceCodeRecord>, AuthError> {
        let row = sqlx::query(
            "SELECT client_id, user_id, scopes, approved, expires_at
             FROM device_codes WHERE device_code_hash = $1",
        )
        .bind(device_code_hash)
        .fetch_optional(self.pool())
        .await
        .map_err(|e| AuthError::Internal(e.to_string()))?;

        Ok(row.map(|r| DeviceCodeRecord {
            client_id: r.get("client_id"),
            user_id: r.get("user_id"),
            scopes: r.get("scopes"),
            approved: r.get("approved"),
            expires_at: r.get("expires_at"),
        }))
    }

    pub async fn approve_device_code(
        &self,
        user_code: &str,
        user_id: Uuid,
    ) -> Result<Option<Uuid>, AuthError> {
        let row = sqlx::query(
            "UPDATE device_codes
             SET approved = TRUE, user_id = $2
             WHERE user_code = $1 AND expires_at > NOW() AND approved = FALSE
             RETURNING client_id",
        )
        .bind(user_code)
        .bind(user_id)
        .fetch_optional(self.pool())
        .await
        .map_err(|e| AuthError::Internal(e.to_string()))?;
        Ok(row.map(|r| r.get("client_id")))
    }

    pub async fn delete_device_code(&self, device_code_hash: &str) -> Result<(), AuthError> {
        sqlx::query("DELETE FROM device_codes WHERE device_code_hash = $1")
            .bind(device_code_hash)
            .execute(self.pool())
            .await
            .map_err(|e| AuthError::Internal(e.to_string()))?;
        Ok(())
    }

    pub async fn purge_expired_device_codes(&self) -> Result<u64, AuthError> {
        let result = sqlx::query("DELETE FROM device_codes WHERE expires_at < NOW()")
            .execute(self.pool())
            .await
            .map_err(|e| AuthError::Internal(e.to_string()))?;
        Ok(result.rows_affected())
    }

    pub async fn get_user_profile(
        &self,
        user_id: Uuid,
        website_id: Uuid,
    ) -> Result<Option<(Option<String>, Option<String>, Option<String>)>, AuthError> {
        let row = sqlx::query(
            "SELECT display_name, avatar_url, locale FROM user_profiles
             WHERE user_id = $1 AND website_id = $2",
        )
        .bind(user_id)
        .bind(website_id)
        .fetch_optional(self.pool())
        .await
        .map_err(|e| AuthError::Internal(e.to_string()))?;
        Ok(row.map(|r| {
            (
                r.get("display_name"),
                r.get("avatar_url"),
                r.get("locale"),
            )
        }))
    }

    pub async fn upsert_user_profile(
        &self,
        user_id: Uuid,
        website_id: Uuid,
        display_name: Option<&str>,
        avatar_url: Option<&str>,
        locale: Option<&str>,
    ) -> Result<(), AuthError> {
        sqlx::query(
            "INSERT INTO user_profiles (user_id, website_id, display_name, avatar_url, locale)
             VALUES ($1, $2, $3, $4, $5)
             ON CONFLICT (user_id, website_id) DO UPDATE
             SET display_name = COALESCE(EXCLUDED.display_name, user_profiles.display_name),
                 avatar_url = COALESCE(EXCLUDED.avatar_url, user_profiles.avatar_url),
                 locale = COALESCE(EXCLUDED.locale, user_profiles.locale),
                 updated_at = NOW()",
        )
        .bind(user_id)
        .bind(website_id)
        .bind(display_name)
        .bind(avatar_url)
        .bind(locale)
        .execute(self.pool())
        .await
        .map_err(|e| AuthError::Internal(e.to_string()))?;
        Ok(())
    }
}
