use std::sync::Arc;

use authsvc_core::{AccountRepository, AuthError, NotificationSender};
use authsvc_idp::ProviderRegistry;
use authsvc_policy::{casbin::CasbinEvaluator, openfga::OpenFgaEvaluator, rbac, CompositeEvaluator, PolicyBackend};
use authsvc_policy::rbac::RbacEvaluator;
use chrono::{Duration, Utc};
use deadpool_redis::redis::AsyncCommands;
use uuid::Uuid;

use crate::{
    config::Config,
    crypto::jwt::{JwtKeyStore, SharedJwtKeyStore},
    middleware::RateLimiter,
    services::{
        notifications::build_notifier,
        webauthn::WebAuthnService,
    },
    stores::{PostgresStore, RedisSessionStore},
};

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub store: PostgresStore,
    pub sessions: RedisSessionStore,
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
        store.migrate().await?;
        AccountRepository::ensure_default(&store).await?;

        let jwt = JwtKeyStore::load_from_db(
            &store,
            &config.issuer,
            config.access_token_ttl_secs,
            config.jwt_key_grace_secs,
            config.jwt_private_key_pem.clone(),
            config.jwt_public_key_pem.clone(),
        )
        .await?;

        let rate_limiter = RateLimiter::new(
            sessions.pool().clone(),
            config.rate_limit_per_minute,
        );

        let rbac = RbacEvaluator::new(Arc::new(store.clone()) as Arc<dyn rbac::PermissionLoader>);
        let casbin = CasbinEvaluator::new(Arc::new(store.clone()) as Arc<dyn authsvc_policy::casbin::CasbinPolicyLoader>);
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
            store,
            sessions,
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
            self.store.set_locked_until(user_id, until).await?;
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
        self.store
            .audit(account_id, actor, action, resource, ip, metadata)
            .await
    }
}
