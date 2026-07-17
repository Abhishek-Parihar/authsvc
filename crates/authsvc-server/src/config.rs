use std::env;

#[derive(Debug, Clone)]
pub struct Config {
    pub host: String,
    pub port: u16,
    pub issuer: String,
    pub database_url: String,
    pub redis_url: String,
    pub access_token_ttl_secs: u64,
    pub refresh_token_ttl_secs: u64,
    pub session_ttl_secs: u64,
    pub jwt_private_key_pem: Option<String>,
    pub jwt_public_key_pem: Option<String>,
    pub default_tenant_slug: String,
}

impl Config {
    pub fn from_env() -> anyhow::Result<Self> {
        Ok(Self {
            host: env::var("AUTHSVC_HOST").unwrap_or_else(|_| "0.0.0.0".into()),
            port: env::var("AUTHSVC_PORT")
                .unwrap_or_else(|_| "8080".into())
                .parse()?,
            issuer: env::var("AUTHSVC_ISSUER")
                .unwrap_or_else(|_| "http://localhost:8080".into()),
            database_url: env::var("DATABASE_URL").expect("DATABASE_URL is required"),
            redis_url: env::var("REDIS_URL")
                .unwrap_or_else(|_| "redis://127.0.0.1:6379".into()),
            access_token_ttl_secs: env::var("ACCESS_TOKEN_TTL_SECS")
                .unwrap_or_else(|_| "900".into())
                .parse()?,
            refresh_token_ttl_secs: env::var("REFRESH_TOKEN_TTL_SECS")
                .unwrap_or_else(|_| "604800".into())
                .parse()?,
            session_ttl_secs: env::var("SESSION_TTL_SECS")
                .unwrap_or_else(|_| "86400".into())
                .parse()?,
            jwt_private_key_pem: env::var("JWT_PRIVATE_KEY_PEM").ok(),
            jwt_public_key_pem: env::var("JWT_PUBLIC_KEY_PEM").ok(),
            default_tenant_slug: env::var("DEFAULT_TENANT_SLUG")
                .unwrap_or_else(|_| "default".into()),
        })
    }
}
