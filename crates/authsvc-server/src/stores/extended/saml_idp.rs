use authsvc_core::AuthError;
use chrono::{DateTime, Utc};
use sqlx::Row;
use uuid::Uuid;

use super::super::PostgresStore;

#[derive(Debug, Clone)]
pub struct SamlServiceProvider {
    pub id: Uuid,
    pub account_id: Uuid,
    pub name: String,
    pub entity_id: String,
    pub acs_url: String,
    pub slo_url: Option<String>,
    pub sp_cert_pem: Option<String>,
    pub want_authn_requests_signed: bool,
}

#[derive(Debug, Clone)]
pub struct SamlPendingAuthn {
    pub id: Uuid,
    pub account_id: Uuid,
    pub sp_id: Uuid,
    pub request_id: String,
    pub relay_state: Option<String>,
    pub acs_url: String,
    pub sp_entity_id: String,
}

impl PostgresStore {
    pub async fn create_saml_sp(
        &self,
        account_id: Uuid,
        name: &str,
        entity_id: &str,
        acs_url: &str,
        slo_url: Option<&str>,
        sp_cert_pem: Option<&str>,
        want_signed: bool,
    ) -> Result<SamlServiceProvider, AuthError> {
        let id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO saml_service_providers (id, account_id, name, entity_id, acs_url, slo_url, sp_cert_pem, want_authn_requests_signed)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8)",
        )
        .bind(id)
        .bind(account_id)
        .bind(name)
        .bind(entity_id)
        .bind(acs_url)
        .bind(slo_url)
        .bind(sp_cert_pem)
        .bind(want_signed)
        .execute(self.pool())
        .await
        .map_err(|e| AuthError::Internal(e.to_string()))?;
        Ok(SamlServiceProvider {
            id,
            account_id,
            name: name.to_string(),
            entity_id: entity_id.to_string(),
            acs_url: acs_url.to_string(),
            slo_url: slo_url.map(str::to_string),
            sp_cert_pem: sp_cert_pem.map(str::to_string),
            want_authn_requests_signed: want_signed,
        })
    }

    pub async fn list_saml_sps(&self, account_id: Uuid) -> Result<Vec<SamlServiceProvider>, AuthError> {
        let rows = sqlx::query(
            "SELECT id, account_id, name, entity_id, acs_url, slo_url, sp_cert_pem, want_authn_requests_signed
             FROM saml_service_providers WHERE account_id = $1 ORDER BY name",
        )
        .bind(account_id)
        .fetch_all(self.pool())
        .await
        .map_err(|e| AuthError::Internal(e.to_string()))?;
        Ok(rows.into_iter().map(map_saml_sp).collect())
    }

    pub async fn find_saml_sp_by_entity(
        &self,
        account_id: Uuid,
        entity_id: &str,
    ) -> Result<Option<SamlServiceProvider>, AuthError> {
        let row = sqlx::query(
            "SELECT id, account_id, name, entity_id, acs_url, slo_url, sp_cert_pem, want_authn_requests_signed
             FROM saml_service_providers WHERE account_id = $1 AND entity_id = $2",
        )
        .bind(account_id)
        .bind(entity_id)
        .fetch_optional(self.pool())
        .await
        .map_err(|e| AuthError::Internal(e.to_string()))?;
        Ok(row.map(map_saml_sp))
    }

    pub async fn delete_saml_sp(&self, account_id: Uuid, id: Uuid) -> Result<(), AuthError> {
        let result = sqlx::query(
            "DELETE FROM saml_service_providers WHERE id = $1 AND account_id = $2",
        )
        .bind(id)
        .bind(account_id)
        .execute(self.pool())
        .await
        .map_err(|e| AuthError::Internal(e.to_string()))?;
        if result.rows_affected() == 0 {
            return Err(AuthError::NotFound("saml service provider".into()));
        }
        Ok(())
    }

    pub async fn store_saml_pending_authn(
        &self,
        id: Uuid,
        account_id: Uuid,
        sp_id: Uuid,
        request_id: &str,
        relay_state: Option<&str>,
        acs_url: &str,
        sp_entity_id: &str,
        expires_at: DateTime<Utc>,
    ) -> Result<(), AuthError> {
        sqlx::query(
            "INSERT INTO saml_pending_authn (id, account_id, sp_id, request_id, relay_state, acs_url, sp_entity_id, expires_at)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8)",
        )
        .bind(id)
        .bind(account_id)
        .bind(sp_id)
        .bind(request_id)
        .bind(relay_state)
        .bind(acs_url)
        .bind(sp_entity_id)
        .bind(expires_at)
        .execute(self.pool())
        .await
        .map_err(|e| AuthError::Internal(e.to_string()))?;
        Ok(())
    }

    pub async fn consume_saml_pending_authn(
        &self,
        id: Uuid,
    ) -> Result<Option<SamlPendingAuthn>, AuthError> {
        let row = sqlx::query(
            "DELETE FROM saml_pending_authn
             WHERE id = $1 AND expires_at > NOW()
             RETURNING account_id, sp_id, request_id, relay_state, acs_url, sp_entity_id",
        )
        .bind(id)
        .fetch_optional(self.pool())
        .await
        .map_err(|e| AuthError::Internal(e.to_string()))?;
        Ok(row.map(|r| SamlPendingAuthn {
            id,
            account_id: r.get("account_id"),
            sp_id: r.get("sp_id"),
            request_id: r.get("request_id"),
            relay_state: r.get("relay_state"),
            acs_url: r.get("acs_url"),
            sp_entity_id: r.get("sp_entity_id"),
        }))
    }

    pub async fn purge_expired_saml_pending(&self) -> Result<u64, AuthError> {
        let result = sqlx::query("DELETE FROM saml_pending_authn WHERE expires_at < NOW()")
            .execute(self.pool())
            .await
            .map_err(|e| AuthError::Internal(e.to_string()))?;
        Ok(result.rows_affected())
    }

    pub async fn search_users_by_email(
        &self,
        email_prefix: &str,
        limit: i64,
    ) -> Result<Vec<serde_json::Value>, AuthError> {
        let pattern = format!("{}%", email_prefix.to_lowercase());
        let rows = sqlx::query(
            "SELECT id, email, display_name, status, created_at
             FROM users
             WHERE LOWER(email) LIKE $1 AND deleted_at IS NULL
             ORDER BY email
             LIMIT $2",
        )
        .bind(pattern)
        .bind(limit)
        .fetch_all(self.pool())
        .await
        .map_err(|e| AuthError::Internal(e.to_string()))?;
        Ok(rows
            .into_iter()
            .map(|r| {
                serde_json::json!({
                    "id": r.get::<Uuid, _>("id"),
                    "email": r.get::<String, _>("email"),
                    "display_name": r.get::<Option<String>, _>("display_name"),
                    "status": r.get::<String, _>("status"),
                    "created_at": r.get::<DateTime<Utc>, _>("created_at"),
                })
            })
            .collect())
    }

    pub async fn list_account_audit_events(
        &self,
        account_id: Uuid,
        limit: i64,
    ) -> Result<Vec<serde_json::Value>, AuthError> {
        let mut tx = self.pool().begin().await.map_err(|e| AuthError::Internal(e.to_string()))?;
        sqlx::query("SELECT set_config('app.account_id', $1, true)")
            .bind(account_id.to_string())
            .execute(&mut *tx)
            .await
            .map_err(|e| AuthError::Internal(e.to_string()))?;
        let rows = sqlx::query(
            "SELECT action, resource, actor_id, ip_address, metadata, created_at
             FROM audit_events
             WHERE account_id = $1
             ORDER BY created_at DESC
             LIMIT $2",
        )
        .bind(account_id)
        .bind(limit)
        .fetch_all(&mut *tx)
        .await
        .map_err(|e| AuthError::Internal(e.to_string()))?;
        tx.commit().await.map_err(|e| AuthError::Internal(e.to_string()))?;
        Ok(rows
            .into_iter()
            .map(|r| {
                serde_json::json!({
                    "action": r.get::<String, _>("action"),
                    "resource": r.get::<Option<String>, _>("resource"),
                    "actor_id": r.get::<Option<String>, _>("actor_id"),
                    "ip_address": r.get::<Option<String>, _>("ip_address"),
                    "metadata": r.get::<serde_json::Value, _>("metadata"),
                    "created_at": r.get::<DateTime<Utc>, _>("created_at"),
                })
            })
            .collect())
    }
}

fn map_saml_sp(r: sqlx::postgres::PgRow) -> SamlServiceProvider {
    SamlServiceProvider {
        id: r.get("id"),
        account_id: r.get("account_id"),
        name: r.get("name"),
        entity_id: r.get("entity_id"),
        acs_url: r.get("acs_url"),
        slo_url: r.get("slo_url"),
        sp_cert_pem: r.get("sp_cert_pem"),
        want_authn_requests_signed: r.get("want_authn_requests_signed"),
    }
}
