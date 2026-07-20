use authsvc_core::AuthError;
use sqlx::Row;
use uuid::Uuid;

use super::super::PostgresStore;

impl PostgresStore {
    pub async fn store_webauthn_credential(
        &self,
        user_id: Uuid,
        credential_id: &[u8],
        public_key: &[u8],
        name: Option<&str>,
    ) -> Result<Uuid, AuthError> {
        let id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO webauthn_credentials (id, user_id, credential_id, public_key, sign_count, name)
             VALUES ($1,$2,$3,$4,0,$5)",
        )
        .bind(id)
        .bind(user_id)
        .bind(credential_id)
        .bind(public_key)
        .bind(name)
        .execute(self.pool())
        .await
        .map_err(|e| AuthError::Internal(e.to_string()))?;
        Ok(id)
    }

    pub async fn list_webauthn_credentials(&self, user_id: Uuid) -> Result<Vec<authsvc_core::WebAuthnCredential>, AuthError> {
        let rows = sqlx::query(
            "SELECT id, user_id, credential_id, public_key, sign_count, name FROM webauthn_credentials WHERE user_id = $1",
        )
        .bind(user_id)
        .fetch_all(self.pool())
        .await
        .map_err(|e| AuthError::Internal(e.to_string()))?;
        Ok(rows
            .into_iter()
            .map(|r| authsvc_core::WebAuthnCredential {
                id: r.get("id"),
                user_id: r.get("user_id"),
                credential_id: r.get("credential_id"),
                public_key: r.get("public_key"),
                sign_count: r.get("sign_count"),
                name: r.get("name"),
            })
            .collect())
    }

    pub async fn update_webauthn_sign_count(&self, id: Uuid, sign_count: i64) -> Result<(), AuthError> {
        sqlx::query("UPDATE webauthn_credentials SET sign_count = $2 WHERE id = $1")
            .bind(id)
            .bind(sign_count)
            .execute(self.pool())
            .await
            .map_err(|e| AuthError::Internal(e.to_string()))?;
        Ok(())
    }

}
