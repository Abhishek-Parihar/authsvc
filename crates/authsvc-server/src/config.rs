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
    #[serde(default = "default_tenant")]
    pub default_tenant_slug: String,
    pub bootstrap_secret: Option<String>,
    #[serde(default = "default_env")]
    pub env: String,
    #[serde(default)]
    pub allowed_origins: Vec<String>,
    #[serde(default = "default_lockout_max")]
    pub lockout_max_attempts: u32,
    #[serde(default = "default_lockout_secs")]
    pub lockout_duration_secs: u64,
    #[serde(default = "default_rate_limit")]
    pub rate_limit_per_minute: u32,
    pub mfa_encryption_key: Option<String>,
    #[serde(default = "default_policy_backend")]
    pub policy_backend: String,
    pub openfga_url: Option<String>,
    pub otel_endpoint: Option<String>,
    #[serde(default)]
    pub cookie_secure: bool,
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
fn default_tenant() -> String {
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

impl Config {
    pub fn from_env() -> anyhow::Result<Self> {
        let mut cfg: Config = Figment::new()
            .merge(Env::raw())
            .extract()
            .map_err(|e| anyhow::anyhow!("config error: {e}"))?;

        if cfg.allowed_origins.is_empty() {
            if let Ok(origins) = std::env::var("ALLOWED_ORIGINS") {
                cfg.allowed_origins = origins
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect();
            }
        }

        if cfg.env == "production" {
            if cfg.jwt_private_key_pem.is_none() || cfg.jwt_public_key_pem.is_none() {
                anyhow::bail!("JWT_PRIVATE_KEY_PEM and JWT_PUBLIC_KEY_PEM required in production");
            }
        }

        Ok(cfg)
    }

    pub fn is_production(&self) -> bool {
        self.env == "production"
    }
}
