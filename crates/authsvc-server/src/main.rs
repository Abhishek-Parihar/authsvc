mod config;
mod crypto;
mod handlers;
mod policy;
mod services;
mod stores;

use std::sync::Arc;

use axum::{
    routing::{get, post},
    Router,
};
use handlers::{
    auth::{create_client, register, revoke, token},
    authz::check,
    health,
    oidc::{jwks, openid_configuration},
    SharedState,
};
use sqlx::postgres::PgPoolOptions;
use tower_http::{cors::CorsLayer, trace::TraceLayer};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use crate::{
    config::Config,
    crypto::jwt::JwtSigner,
    services::auth::AppState,
    stores::{PostgresStore, RedisSessionStore},
};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "authsvc_server=debug,tower_http=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let config = Config::from_env()?;

    let pool = PgPoolOptions::new()
        .max_connections(10)
        .connect(&config.database_url)
        .await?;

    let store = PostgresStore::new(pool);
    let sessions = RedisSessionStore::new(&config.redis_url)?;
    let jwt = JwtSigner::new(
        &config.issuer,
        config.access_token_ttl_secs,
        config.jwt_private_key_pem.clone(),
        config.jwt_public_key_pem.clone(),
    )?;

    let state = Arc::new(
        AppState::new(
            store,
            sessions,
            jwt,
            config.refresh_token_ttl_secs,
            config.session_ttl_secs,
            config.default_tenant_slug,
        )
        .await?,
    );

    let app = Router::new()
        .route("/health", get(health))
        .route(
            "/.well-known/openid-configuration",
            get(openid_configuration),
        )
        .route("/.well-known/jwks.json", get(jwks))
        .route("/oauth/token", post(token))
        .route("/oauth/revoke", post(revoke))
        .route("/v1/auth/register", post(register))
        .route("/v1/clients", post(create_client))
        .route("/v1/authz/check", post(check))
        .layer(CorsLayer::permissive())
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    let addr = format!("{}:{}", config.host, config.port);
    tracing::info!("authsvc listening on {addr}");
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}
