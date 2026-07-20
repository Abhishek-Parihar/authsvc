use authsvc_core::AuthError;
use sqlx::Row;
use uuid::Uuid;

use super::super::PostgresStore;

impl PostgresStore {
    pub async fn audit(
        &self,
        account_id: Option<Uuid>,
        actor: Option<&str>,
        action: &str,
        resource: Option<&str>,
        ip: Option<&str>,
        metadata: serde_json::Value,
    ) -> Result<(), AuthError> {
        sqlx::query(
            "INSERT INTO audit_events (id, account_id, actor_id, action, resource, ip_address, metadata) VALUES ($1,$2,$3,$4,$5,$6,$7)",
        )
        .bind(Uuid::new_v4())
        .bind(account_id)
        .bind(actor)
        .bind(action)
        .bind(resource)
        .bind(ip)
        .bind(metadata)
        .execute(self.pool())
        .await
        .map_err(|e| AuthError::Internal(e.to_string()))?;
        Ok(())
    }

    pub async fn create_webhook(&self, account_id: Uuid, url: &str, secret: &str, events: &[String]) -> Result<Uuid, AuthError> {
        let id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO webhooks (id, account_id, url, secret, events) VALUES ($1,$2,$3,$4,$5)",
        )
        .bind(id)
        .bind(account_id)
        .bind(url)
        .bind(secret)
        .bind(events)
        .execute(self.pool())
        .await
        .map_err(|e| AuthError::Internal(e.to_string()))?;
        Ok(id)
    }

    pub async fn list_webhooks_for_event(&self, account_id: Uuid, event: &str) -> Result<Vec<(Uuid, String, String)>, AuthError> {
        let rows = sqlx::query(
            "SELECT id, url, secret FROM webhooks WHERE account_id = $1 AND enabled = TRUE AND $2 = ANY(events)",
        )
        .bind(account_id)
        .bind(event)
        .fetch_all(self.pool())
        .await
        .map_err(|e| AuthError::Internal(e.to_string()))?;
        Ok(rows
            .into_iter()
            .map(|r| (r.get("id"), r.get("url"), r.get("secret")))
            .collect())
    }

    pub async fn record_webhook_delivery(
        &self,
        id: Uuid,
        webhook_id: Uuid,
        event: &str,
        status: &str,
        attempts: i32,
        last_error: Option<&str>,
    ) -> Result<(), AuthError> {
        sqlx::query(
            "INSERT INTO webhook_deliveries (id, webhook_id, event, status, attempts, last_error)
             VALUES ($1,$2,$3,$4,$5,$6)
             ON CONFLICT (id) DO UPDATE SET status = $4, attempts = $5, last_error = $6, updated_at = NOW()",
        )
        .bind(id)
        .bind(webhook_id)
        .bind(event)
        .bind(status)
        .bind(attempts)
        .bind(last_error)
        .execute(self.pool())
        .await
        .map_err(|e| AuthError::Internal(e.to_string()))?;
        Ok(())
    }

}
