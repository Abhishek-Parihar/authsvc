use authsvc_core::AuthError;
use sqlx::Row;

use super::super::PostgresStore;

impl PostgresStore {
    pub async fn store_signing_key(
        &self,
        kid: &str,
        public_pem: &str,
        encrypted_private_pem: Option<&str>,
    ) -> Result<(), AuthError> {
        sqlx::query(
            "INSERT INTO signing_keys (kid, public_key_pem, encrypted_private_pem, active)
             VALUES ($1, $2, $3, TRUE)
             ON CONFLICT (kid) DO UPDATE
             SET public_key_pem = $2, encrypted_private_pem = $3, active = TRUE",
        )
        .bind(kid)
        .bind(public_pem)
        .bind(encrypted_private_pem)
        .execute(self.pool())
        .await
        .map_err(|e| AuthError::Internal(e.to_string()))?;
        Ok(())
    }

    pub async fn get_active_signing_key(
        &self,
    ) -> Result<Option<(String, String, Option<String>)>, AuthError> {
        let row = sqlx::query(
            "SELECT kid, public_key_pem, encrypted_private_pem FROM signing_keys
             WHERE active = TRUE ORDER BY created_at DESC LIMIT 1",
        )
        .fetch_optional(self.pool())
        .await
        .map_err(|e| AuthError::Internal(e.to_string()))?;
        Ok(row.map(|r| {
            (
                r.get("kid"),
                r.get("public_key_pem"),
                r.get("encrypted_private_pem"),
            )
        }))
    }

    pub async fn list_signing_keys_for_jwks(
        &self,
        grace_secs: u64,
    ) -> Result<Vec<(String, String)>, AuthError> {
        let rows = sqlx::query(
            "SELECT kid, public_key_pem FROM signing_keys
             WHERE active = TRUE
                OR (rotated_at IS NOT NULL AND rotated_at > NOW() - make_interval(secs => $1::double precision))",
        )
        .bind(grace_secs as f64)
        .fetch_all(self.pool())
        .await
        .map_err(|e| AuthError::Internal(e.to_string()))?;
        Ok(rows
            .into_iter()
            .map(|r| (r.get("kid"), r.get("public_key_pem")))
            .collect())
    }

    pub async fn deactivate_signing_keys(&self) -> Result<(), AuthError> {
        sqlx::query("UPDATE signing_keys SET active = FALSE, rotated_at = NOW() WHERE active = TRUE")
            .execute(self.pool())
            .await
            .map_err(|e| AuthError::Internal(e.to_string()))?;
        Ok(())
    }
}
