mod config;
mod crypto;
mod handlers;
mod middleware;
mod services;
mod stores;

use std::sync::Arc;

use authsvc_idp::{github::GitHubProvider, google::GoogleProvider, ProviderRegistry};
use axum::{
    middleware as axum_mw,
    routing::{get, post},
    Router,
};
use handlers::{
    admin::{
        assign_user_role, create_api_key_handler, create_permission, create_role, create_tenant,
        create_webhook, delete_client, get_tenant, list_clients, revoke_api_key_handler,
        rotate_keys as admin_rotate_keys,
    },
    auth::{
        complete_mfa, create_client, magic_link_send, magic_link_verify, mfa_disable, mfa_enroll,
        mfa_verify, register, revoke, token,
    },
    federation::{federate_callback, federate_start},
    health::{health, ready},
    oidc::{
        authorize, check, introspect, logout, oauth_login, openid_configuration, userinfo, jwks,
    },
    SharedState,
};
use sqlx::postgres::PgPoolOptions;
use tower_http::{
    cors::{Any, CorsLayer},
    trace::TraceLayer,
};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use crate::{
    config::Config,
    crypto::jwt::JwtSigner,
    middleware::{require_admin, require_bootstrap_or_open},
    services::AppState,
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

    let mut idp_registry = ProviderRegistry::new();
    if let (Ok(g_id), Ok(g_sec)) = (
        std::env::var("GOOGLE_CLIENT_ID"),
        std::env::var("GOOGLE_CLIENT_SECRET"),
    ) {
        let redirect = format!("{}/oauth/federate/google/callback", config.issuer);
        if let Ok(p) = GoogleProvider::new(&g_id, &g_sec, &redirect) {
            idp_registry.register(Arc::new(p));
        }
    }
    if let (Ok(gh_id), Ok(gh_sec)) = (
        std::env::var("GITHUB_CLIENT_ID"),
        std::env::var("GITHUB_CLIENT_SECRET"),
    ) {
        let redirect = format!("{}/oauth/federate/github/callback", config.issuer);
        if let Ok(p) = GitHubProvider::new(&gh_id, &gh_sec, &redirect) {
            idp_registry.register(Arc::new(p));
        }
    }

    let state = Arc::new(
        AppState::new(config.clone(), store, sessions, jwt, idp_registry).await?,
    );

    let cors = if state.config.allowed_origins.is_empty() {
        CorsLayer::new()
            .allow_origin(Any)
            .allow_methods(Any)
            .allow_headers(Any)
    } else {
        let origins: Vec<_> = state
            .config
            .allowed_origins
            .iter()
            .filter_map(|o| o.parse().ok())
            .collect();
        CorsLayer::new()
            .allow_origin(origins)
            .allow_methods(Any)
            .allow_headers(Any)
    };

    let public = Router::new()
        .route("/health", get(health))
        .route("/ready", get(ready))
        .route(
            "/.well-known/openid-configuration",
            get(openid_configuration),
        )
        .route("/.well-known/jwks.json", get(jwks))
        .route("/oauth/token", post(token))
        .route("/oauth/revoke", post(revoke))
        .route("/oauth/userinfo", get(userinfo))
        .route("/oauth/introspect", post(introspect))
        .route("/oauth/authorize", get(authorize))
        .route("/oauth/login", post(oauth_login))
        .route("/oauth/logout", post(logout))
        .route("/oauth/mfa", post(complete_mfa))
        .route("/v1/auth/magic-link/send", post(magic_link_send))
        .route("/v1/auth/magic-link/verify", get(magic_link_verify))
        .route("/v1/authz/check", post(check))
        .route("/oauth/federate/:provider", get(federate_start))
        .route("/oauth/federate/:provider/callback", get(federate_callback));

    let bootstrap = Router::new()
        .route("/v1/auth/register", post(register))
        .layer(axum_mw::from_fn_with_state(
            state.clone(),
            require_bootstrap_or_open,
        ));

    let admin = Router::new()
        .route("/v1/clients", post(create_client).get(list_clients))
        .route("/v1/clients/:id", axum::routing::delete(delete_client))
        .route("/v1/tenants", post(create_tenant))
        .route("/v1/tenants/:id", get(get_tenant))
        .route("/v1/roles", post(create_role))
        .route("/v1/permissions", post(create_permission))
        .route("/v1/users/:id/roles", post(assign_user_role))
        .route("/v1/api-keys", post(create_api_key_handler))
        .route("/v1/api-keys/:id", axum::routing::delete(revoke_api_key_handler))
        .route("/v1/webhooks", post(create_webhook))
        .route("/v1/keys/rotate", post(admin_rotate_keys))
        .route("/v1/mfa/enroll", post(mfa_enroll))
        .route("/v1/mfa/verify", post(mfa_verify))
        .route("/v1/mfa/disable", post(mfa_disable))
        .layer(axum_mw::from_fn_with_state(state.clone(), require_admin));

    let app = public
        .merge(bootstrap)
        .merge(admin)
        .layer(cors)
        .layer(TraceLayer::new_for_http())
        .with_state(state.clone());

    let addr = format!("{}:{}", config.host, config.port);
    tracing::info!("authsvc listening on {addr}");
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}
