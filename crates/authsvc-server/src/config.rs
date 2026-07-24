use figment::{providers::Env, Figment};
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    #[serde(default = "default_host")]
    pub host: String,
    #[serde(default = "default_port")]
    pub port: u16,
    #[serde(default = "default_issuer")]
    pub issuer: String,
    pub database_url: String,
    #[serde(default = "default_redis")]
    pub redis_url: String,
    #[serde(default = "default_access_ttl")]
    pub access_token_ttl_secs: u64,
    #[serde(default = "default_refresh_ttl")]
    pub refresh_token_ttl_secs: u64,
    #[serde(default = "default_session_ttl")]
    pub session_ttl_secs: u64,
    pub jwt_private_key_pem: Option<String>,
    pub jwt_public_key_pem: Option<String>,
    #[serde(default = "default_account")]
    pub default_account_slug: String,
    #[serde(default = "default_website")]
    pub default_website_slug: String,
    pub bootstrap_secret: Option<String>,
    #[serde(default = "default_env")]
    pub env: String,
    #[serde(default, skip)]
    pub allowed_origins: Vec<String>,
    #[serde(default = "default_lockout_max")]
    pub lockout_max_attempts: u32,
    #[serde(default = "default_lockout_secs")]
    pub lockout_duration_secs: u64,
    #[serde(default = "default_rate_limit")]
    pub rate_limit_per_minute: u32,
    pub mfa_encryption_key: Option<String>,
    pub data_encryption_key: Option<String>,
    pub kms_http_url: Option<String>,
    pub jwt_kms_http_url: Option<String>,
    pub jwt_kms_key_id: Option<String>,
    #[serde(default)]
    pub disable_password_grant: bool,
    #[serde(default = "default_database_max_connections")]
    pub database_max_connections: u32,
    pub database_read_url: Option<String>,
    #[serde(default = "default_deployment_mode")]
    pub deployment_mode: String,
    pub audit_export_webhook: Option<String>,
    #[serde(default)]
    pub cookie_secure: bool,
    #[serde(default = "default_policy_backend")]
    pub policy_backend: String,
    pub openfga_url: Option<String>,
    pub otel_endpoint: Option<String>,
    pub webauthn_rp_id: Option<String>,
    #[serde(default = "default_jwt_key_grace_secs")]
    pub jwt_key_grace_secs: u64,
    pub google_client_id: Option<String>,
    pub google_client_secret: Option<String>,
    pub github_client_id: Option<String>,
    pub github_client_secret: Option<String>,
    pub microsoft_client_id: Option<String>,
    pub microsoft_client_secret: Option<String>,
    pub microsoft_tenant: Option<String>,
    #[serde(default = "default_audit_retention_days")]
    pub audit_retention_days: u64,
    #[serde(default = "default_dsar_artifact_retention_days")]
    pub dsar_artifact_retention_days: u64,
    #[serde(default = "default_migrate_on_start")]
    pub migrate_on_start: bool,
    pub database_migrator_url: Option<String>,
    pub metrics_bearer_token: Option<String>,
}

fn default_host() -> String {
    "0.0.0.0".into()
}
fn default_port() -> u16 {
    8080
}
fn default_issuer() -> String {
    "http://localhost:8080".into()
}
fn default_redis() -> String {
    "redis://127.0.0.1:6379".into()
}
fn default_access_ttl() -> u64 {
    900
}
fn default_refresh_ttl() -> u64 {
    604800
}
fn default_session_ttl() -> u64 {
    86400
}
fn default_account() -> String {
    "default".into()
}
fn default_website() -> String {
    "default".into()
}
fn default_env() -> String {
    "development".into()
}
fn default_lockout_max() -> u32 {
    5
}
fn default_lockout_secs() -> u64 {
    900
}
fn default_rate_limit() -> u32 {
    60
}
fn default_policy_backend() -> String {
    "rbac".into()
}
fn default_jwt_key_grace_secs() -> u64 {
    86400
}
fn default_database_max_connections() -> u32 {
    10
}
fn default_deployment_mode() -> String {
    "self_hosted".into()
}
fn default_audit_retention_days() -> u64 {
    365
}
fn default_dsar_artifact_retention_days() -> u64 {
    30
}
fn default_migrate_on_start() -> bool {
    true
}

impl Config {
    pub fn from_env() -> anyhow::Result<Self> {
        let mut cfg: Config = Figment::new()
            .merge(Env::raw())
            .extract()
            .map_err(|e| anyhow::anyhow!("config error: {e}"))?;

        if let Ok(origins) = std::env::var("ALLOWED_ORIGINS") {
            cfg.allowed_origins = origins
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
        }

        fn empty_as_none(value: Option<String>) -> Option<String> {
            value.filter(|s| !s.trim().is_empty())
        }
        cfg.jwt_private_key_pem = empty_as_none(cfg.jwt_private_key_pem);
        cfg.jwt_public_key_pem = empty_as_none(cfg.jwt_public_key_pem);
        cfg.bootstrap_secret = empty_as_none(cfg.bootstrap_secret);
        cfg.mfa_encryption_key = empty_as_none(cfg.mfa_encryption_key);
        cfg.data_encryption_key = empty_as_none(cfg.data_encryption_key);
        cfg.kms_http_url = empty_as_none(cfg.kms_http_url);
        cfg.jwt_kms_http_url = empty_as_none(cfg.jwt_kms_http_url);
        cfg.jwt_kms_key_id = empty_as_none(cfg.jwt_kms_key_id);
        cfg.database_read_url = empty_as_none(cfg.database_read_url);
        cfg.audit_export_webhook = empty_as_none(cfg.audit_export_webhook);
        cfg.openfga_url = empty_as_none(cfg.openfga_url);
        cfg.otel_endpoint = empty_as_none(cfg.otel_endpoint);
        cfg.webauthn_rp_id = empty_as_none(cfg.webauthn_rp_id);
        cfg.google_client_id = empty_as_none(cfg.google_client_id);
        cfg.google_client_secret = empty_as_none(cfg.google_client_secret);
        cfg.github_client_id = empty_as_none(cfg.github_client_id);
        cfg.github_client_secret = empty_as_none(cfg.github_client_secret);
        cfg.microsoft_client_id = empty_as_none(cfg.microsoft_client_id);
        cfg.microsoft_client_secret = empty_as_none(cfg.microsoft_client_secret);
        cfg.microsoft_tenant = empty_as_none(cfg.microsoft_tenant);
        cfg.database_migrator_url = empty_as_none(cfg.database_migrator_url);
        cfg.metrics_bearer_token = empty_as_none(cfg.metrics_bearer_token);

        if cfg.env == "production" {
            if cfg.jwt_public_key_pem.is_none() {
                anyhow::bail!("JWT_PUBLIC_KEY_PEM required in production");
            }
            if cfg.jwt_kms_http_url.is_none()
                && (cfg.jwt_private_key_pem.is_none() || cfg.jwt_public_key_pem.is_none())
            {
                anyhow::bail!(
                    "JWT_PRIVATE_KEY_PEM and JWT_PUBLIC_KEY_PEM required in production (or JWT_KMS_HTTP_URL with JWT_PUBLIC_KEY_PEM)"
                );
            }
            if cfg.data_encryption_key.is_none() && cfg.mfa_encryption_key.is_none() {
                anyhow::bail!("DATA_ENCRYPTION_KEY or MFA_ENCRYPTION_KEY required in production");
            }
            if cfg.allowed_origins.is_empty() {
                anyhow::bail!("ALLOWED_ORIGINS required in production");
            }
            if cfg.metrics_bearer_token.is_none() {
                anyhow::bail!("METRICS_BEARER_TOKEN required in production");
            }
            if !cfg.cookie_secure {
                cfg.cookie_secure = true;
            }
            cfg.disable_password_grant = true;
        }

        Ok(cfg)
    }

    pub fn is_production(&self) -> bool {
        self.env == "production"
    }

    pub fn is_managed_saas(&self) -> bool {
        self.deployment_mode == "managed_saas"
    }
}
