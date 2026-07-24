use std::sync::Arc;

use authsvc_core::{AuthError, DataKeyStore, NotificationSender};
use authsvc_idp::ProviderRegistry;
use authsvc_policy::{casbin::CasbinEvaluator, openfga::OpenFgaEvaluator, rbac, CompositeEvaluator, PolicyBackend};
use authsvc_policy::rbac::RbacEvaluator;
use chrono::{Duration, Utc};
use deadpool_redis::redis::AsyncCommands;
use uuid::Uuid;

use crate::{
    config::Config,
    crypto::{
        data_keys::build_data_key_store,
        jwt::{JwtKeyStore, SharedJwtKeyStore},
    },
    middleware::RateLimiter,
    services::{
        notifications::build_notifier,
        webauthn::WebAuthnService,
    },
    stores::{
        cached_permissions::CachedPermissionLoader, PostgresStore, RedisSessionStore,
        Repositories,
    },
};

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub repos: Repositories,
    pub sessions: RedisSessionStore,
    pub data_keys: Arc<dyn DataKeyStore>,
    pub jwt: SharedJwtKeyStore,
    pub rate_limiter: RateLimiter,
    pub policy: Arc<CompositeEvaluator>,
    pub idp_registry: Arc<ProviderRegistry>,
    pub webauthn: Option<Arc<WebAuthnService>>,
    pub notifier: Arc<dyn NotificationSender>,
}

impl AppState {
    pub async fn new(
        config: Config,
        store: PostgresStore,
        sessions: RedisSessionStore,
        idp_registry: ProviderRegistry,
        webauthn: Option<Arc<WebAuthnService>>,
    ) -> Result<Self, AuthError> {
        let repos = Repositories::new(store);
        if config.migrate_on_start {
            repos.postgres().migrate().await?;
        }
        repos.accounts().ensure_default().await?;

        let data_keys = build_data_key_store(
            config.data_encryption_key.as_deref(),
            config.mfa_encryption_key.as_deref(),
            config.kms_http_url.as_deref(),
            config.is_production(),
        )?;

        let jwt = JwtKeyStore::load(
            repos.signing_keys(),
            &data_keys,
            &config.issuer,
            config.access_token_ttl_secs,
            config.jwt_key_grace_secs,
            config.jwt_private_key_pem.clone(),
            config.jwt_public_key_pem.clone(),
            config.jwt_kms_http_url.clone(),
            config.jwt_kms_key_id.clone(),
            !config.is_production(),
        )
        .await?;

        let rate_limiter = RateLimiter::new(
            sessions.pool().clone(),
            config.rate_limit_per_minute,
        );

        let postgres = repos.postgres().clone();
        let permission_loader = Arc::new(CachedPermissionLoader::new(
            Arc::new(postgres.clone()),
            sessions.clone(),
        )) as Arc<dyn rbac::PermissionLoader>;
        let rbac = RbacEvaluator::new(permission_loader);
        let casbin = CasbinEvaluator::new(
            Arc::new(postgres.clone()) as Arc<dyn authsvc_policy::casbin::CasbinPolicyLoader>,
        );
        let openfga = OpenFgaEvaluator::new(
            config.openfga_url.clone().unwrap_or_else(|| "http://localhost:8081".into()),
            "default",
        );
        let policy = Arc::new(CompositeEvaluator::new(
            PolicyBackend::parse(&config.policy_backend),
            rbac,
            casbin,
            openfga,
        ));

        let notifier = Arc::from(build_notifier());

        Ok(Self {
            config: Arc::new(config),
            repos,
            sessions,
            data_keys,
            jwt: Arc::new(jwt),
            rate_limiter,
            policy,
            idp_registry: Arc::new(idp_registry),
            webauthn,
            notifier,
        })
    }

    pub async fn record_failed_login(&self, email: &str, user_id: Uuid) -> Result<(), AuthError> {
        let key = format!("login_fail:{email}");
        let mut conn = self
            .sessions
            .pool()
            .get()
            .await
            .map_err(|e| AuthError::Internal(e.to_string()))?;
        let count: i64 = conn
            .incr(&key, 1i64)
            .await
            .map_err(|e| AuthError::Internal(e.to_string()))?;
        if count == 1 {
            let _: () = conn
                .expire(&key, self.config.lockout_duration_secs as i64)
                .await
                .map_err(|e| AuthError::Internal(e.to_string()))?;
        }
        if count >= self.config.lockout_max_attempts as i64 {
            let until = Utc::now() + Duration::seconds(self.config.lockout_duration_secs as i64);
            self.repos.users().set_locked_until(user_id, until).await?;
        }
        Ok(())
    }

    pub async fn clear_failed_login(&self, email: &str) -> Result<(), AuthError> {
        let key = format!("login_fail:{email}");
        let mut conn = self
            .sessions
            .pool()
            .get()
            .await
            .map_err(|e| AuthError::Internal(e.to_string()))?;
        let _: () = conn
            .del(key)
            .await
            .map_err(|e| AuthError::Internal(e.to_string()))?;
        Ok(())
    }

    pub async fn audit(
        &self,
        account_id: Option<Uuid>,
        actor: Option<&str>,
        action: &str,
        resource: Option<&str>,
        ip: Option<&str>,
        metadata: serde_json::Value,
    ) -> Result<(), AuthError> {
        self.repos
            .audit()
            .audit(account_id, actor, action, resource, ip, metadata.clone())
            .await?;

        if let Some(aid) = account_id {
            let state = self.clone();
            let action_owned = action.to_string();
            let resource_owned = resource.map(str::to_string);
            let actor_owned = actor.map(str::to_string);
            let metadata_webhook = metadata.clone();
            tokio::spawn(async move {
                super::ops::dispatch_webhook(
                    &state,
                    aid,
                    &format!("audit.{action_owned}"),
                    serde_json::json!({
                        "action": action_owned,
                        "resource": resource_owned,
                        "actor": actor_owned,
                        "metadata": metadata_webhook,
                    }),
                );
            });
        }

        if let Some(url) = &self.config.audit_export_webhook {
            let client = reqwest::Client::new();
            let body = serde_json::json!({
                "account_id": account_id,
                "actor": actor,
                "action": action,
                "resource": resource,
                "ip": ip,
                "metadata": metadata,
            });
            let url = url.clone();
            tokio::spawn(async move {
                export_audit_to_siem(&client, &url, body).await;
            });
        }

        Ok(())
    }
}

async fn export_audit_to_siem(client: &reqwest::Client, url: &str, body: serde_json::Value) {
    let mut last_error = None;
    for attempt in 1..=3 {
        match client.post(url).json(&body).send().await {
            Ok(resp) if resp.status().is_success() => return,
            Ok(resp) => last_error = Some(format!("HTTP {}", resp.status())),
            Err(e) => last_error = Some(e.to_string()),
        }
        if attempt < 3 {
            tokio::time::sleep(std::time::Duration::from_millis(500 * attempt as u64)).await;
        }
    }
    tracing::warn!(
        error = ?last_error,
        url = url,
        "audit SIEM export failed after retries"
    );
}
