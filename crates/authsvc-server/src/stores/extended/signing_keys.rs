use authsvc_core::AuthError;
use sqlx::Row;

use super::super::PostgresStore;

impl PostgresStore {
    pub async fn store_signing_key(&self, kid: &str, private_pem: &str, public_pem: &str) -> Result<(), AuthError> {
        sqlx::query(
            "INSERT INTO signing_keys (kid, private_key_pem, public_key_pem, active) VALUES ($1,$2,$3,TRUE)
             ON CONFLICT (kid) DO UPDATE SET private_key_pem = $2, public_key_pem = $3, active = TRUE",
        )
        .bind(kid)
        .bind(private_pem)
        .bind(public_pem)
        .execute(self.pool())
        .await
        .map_err(|e| AuthError::Internal(e.to_string()))?;
        Ok(())
    }

    pub async fn get_active_signing_key(
        &self,
    ) -> Result<Option<(String, String, String)>, AuthError> {
        let row = sqlx::query(
            "SELECT kid, private_key_pem, public_key_pem FROM signing_keys
             WHERE active = TRUE ORDER BY created_at DESC LIMIT 1",
        )
        .fetch_optional(self.pool())
        .await
        .map_err(|e| AuthError::Internal(e.to_string()))?;
        Ok(row.map(|r| {
            (
                r.get("kid"),
                r.get("private_key_pem"),
                r.get("public_key_pem"),
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
