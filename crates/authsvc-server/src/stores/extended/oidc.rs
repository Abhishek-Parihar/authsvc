use authsvc_core::AuthError;
use chrono::{DateTime, Utc};
use sqlx::Row;
use uuid::Uuid;

use super::super::PostgresStore;

impl PostgresStore {
    pub async fn store_auth_code(
        &self,
        code: &str,
        client_id: Uuid,
        user_id: Uuid,
        redirect_uri: &str,
        code_challenge: &str,
        scopes: &[String],
        expires_at: DateTime<Utc>,
    ) -> Result<(), AuthError> {
        sqlx::query(
            "INSERT INTO authorization_codes (code, client_id, user_id, redirect_uri, code_challenge, scopes, expires_at)
             VALUES ($1,$2,$3,$4,$5,$6,$7)",
        )
        .bind(code)
        .bind(client_id)
        .bind(user_id)
        .bind(redirect_uri)
        .bind(code_challenge)
        .bind(scopes)
        .bind(expires_at)
        .execute(self.pool())
        .await
        .map_err(|e| AuthError::Internal(e.to_string()))?;
        Ok(())
    }

    pub async fn consume_auth_code(
        &self,
        code: &str,
        redirect_uri: &str,
        code_verifier: &str,
    ) -> Result<Option<(Uuid, Uuid, Vec<String>)>, AuthError> {
        use sha2::{Digest, Sha256};
        let row = sqlx::query(
            "SELECT client_id, user_id, redirect_uri, code_challenge, scopes, expires_at, used
             FROM authorization_codes WHERE code = $1",
        )
        .bind(code)
        .fetch_optional(self.pool())
        .await
        .map_err(|e| AuthError::Internal(e.to_string()))?;

        let Some(r) = row else {
            return Ok(None);
        };
        if r.get::<bool, _>("used") {
            return Err(AuthError::InvalidToken);
        }
        let expires: DateTime<Utc> = r.get("expires_at");
        if expires < Utc::now() {
            return Ok(None);
        }
        if r.get::<String, _>("redirect_uri") != redirect_uri {
            return Err(AuthError::Validation("redirect_uri mismatch".into()));
        }
        let challenge: String = r.get("code_challenge");
        let verifier_hash = base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            Sha256::digest(code_verifier.as_bytes()),
        );
        if challenge != verifier_hash {
            return Err(AuthError::InvalidCredentials);
        }
        sqlx::query("UPDATE authorization_codes SET used = TRUE WHERE code = $1")
            .bind(code)
            .execute(self.pool())
            .await
            .map_err(|e| AuthError::Internal(e.to_string()))?;
        Ok(Some((
            r.get("user_id"),
            r.get("client_id"),
            r.get("scopes"),
        )))
    }

    pub async fn store_login_state(
        &self,
        state: &str,
        client_id: &str,
        redirect_uri: &str,
        code_challenge: &str,
        scopes: &[String],
        expires_at: DateTime<Utc>,
    ) -> Result<(), AuthError> {
        sqlx::query(
            "INSERT INTO login_states (state, client_id, redirect_uri, code_challenge, scopes, expires_at)
             VALUES ($1,$2,$3,$4,$5,$6)",
        )
        .bind(state)
        .bind(client_id)
        .bind(redirect_uri)
        .bind(code_challenge)
        .bind(scopes)
        .bind(expires_at)
        .execute(self.pool())
        .await
        .map_err(|e| AuthError::Internal(e.to_string()))?;
        Ok(())
    }

    pub async fn get_login_state(&self, state: &str) -> Result<Option<(String, String, String, Vec<String>)>, AuthError> {
        let row = sqlx::query(
            "SELECT client_id, redirect_uri, code_challenge, scopes, expires_at FROM login_states WHERE state = $1",
        )
        .bind(state)
        .fetch_optional(self.pool())
        .await
        .map_err(|e| AuthError::Internal(e.to_string()))?;
        let Some(r) = row else {
            return Ok(None);
        };
        let expires: DateTime<Utc> = r.get("expires_at");
        if expires < Utc::now() {
            return Ok(None);
        }
        Ok(Some((
            r.get("client_id"),
            r.get("redirect_uri"),
            r.get("code_challenge"),
            r.get("scopes"),
        )))
    }

}
