use std::sync::Arc;

use authsvc_idp::{
    github::GitHubProvider, google::GoogleProvider, microsoft::MicrosoftProvider, ProviderRegistry,
};
use axum::{
    middleware as axum_mw,
    routing::{get, patch, post},
    Extension, Router,
};
use sqlx::postgres::PgPoolOptions;
use tower_http::{
    cors::{Any, CorsLayer},
    trace::TraceLayer,
};

use crate::{
    config::Config,
    handlers::{
        admin::{
            add_role_inheritance, assign_user_role, create_api_key_handler, create_casbin_rule,
            create_permission, create_role, create_account, create_website, create_webhook,
            create_scim_token_handler, delete_casbin_rule, delete_client, get_account,
            list_casbin_rules, list_clients, remove_role_inheritance, revoke_api_key_handler,
            rotate_keys as admin_rotate_keys,
        },
        auth::{
            complete_mfa, create_client, email_otp_send, email_otp_verify, magic_link_send,
            magic_link_verify, mfa_disable, mfa_enroll, mfa_verify, phone_otp_send,
            phone_otp_verify, register, revoke, select_account, token,
        },
        compliance::compliance_status,
        federation::{federate_callback, federate_start},
        device::{device_approve, device_authorization, device_page},
        health::{health, metrics, ready},
        idp_config::{delete_idp_config, list_idp_configs, upsert_idp_config},
        oidc::{
            authorize, check, introspect, logout_get, logout_post, oauth_login, openid_configuration, userinfo, jwks,
        },
        portal::get_portal_from_map,
        privacy::{delete_user, export_user},
        saml::{saml_acs, saml_login, saml_logout, saml_metadata, saml_slo},
        saml_idp::{
            create_saml_sp, delete_saml_sp, idp_login, idp_metadata, idp_sso_get, idp_sso_post,
            list_audit_events, list_saml_sps, search_users,
        },
        scim::{create_user as scim_create_user, delete_user as scim_delete_user, get_group as scim_get_group, get_user as scim_get_user, list_groups as scim_list_groups, list_users as scim_list_users, patch_group as scim_patch_group, patch_user as scim_patch_user},
        sessions::{list_sessions, revoke_all_sessions, revoke_session},
        ui::{admin_page, login_page},
        admin_session::{create_session as admin_create_session, delete_session as admin_delete_session, session_status as admin_session_status},
        webauthn::{login_begin, login_finish, register_begin, register_finish},
        SharedState,
    },
    middleware::{require_admin, require_authenticated, require_bootstrap_or_open, require_metrics_token, ip_rate_limit, request_metrics, security_headers, set_account_context},
    services::{
        archival::spawn_archival_loop,
        state::AppState,
        webauthn::{rp_id_from_issuer, WebAuthnService},
    },
    stores::{PostgresStore, RedisSessionStore},
};

pub async fn build_state(config: Config) -> anyhow::Result<Arc<AppState>> {
    let pool = PgPoolOptions::new()
        .max_connections(config.database_max_connections)
        .connect(&config.database_url)
        .await?;

    let store = if let Some(read_url) = &config.database_read_url {
        let read_pool = PgPoolOptions::new()
            .max_connections(config.database_max_connections)
            .connect(read_url)
            .await?;
        PostgresStore::with_read_pool(pool, read_pool)
    } else {
        PostgresStore::new(pool)
    };
    let store = if let Some(migrator_url) = &config.database_migrator_url {
        let migrator_pool = PgPoolOptions::new()
            .max_connections(2)
            .connect(migrator_url)
            .await?;
        store.with_migrator_pool(migrator_pool)
    } else {
        store
    };
    let sessions = RedisSessionStore::new(&config.redis_url)?;

    let mut idp_registry = ProviderRegistry::new();
    if let (Some(g_id), Some(g_sec)) = (
        config.google_client_id.clone(),
        config.google_client_secret.clone(),
    ) {
        let redirect = format!("{}/oauth/federate/google/callback", config.issuer);
        if let Ok(p) = GoogleProvider::new(&g_id, &g_sec, &redirect) {
            idp_registry.register(Arc::new(p));
        }
    }
    if let (Some(gh_id), Some(gh_sec)) = (
        config.github_client_id.clone(),
        config.github_client_secret.clone(),
    ) {
        let redirect = format!("{}/oauth/federate/github/callback", config.issuer);
        if let Ok(p) = GitHubProvider::new(&gh_id, &gh_sec, &redirect) {
            idp_registry.register(Arc::new(p));
        }
    }
    if let (Some(ms_id), Some(ms_sec)) = (
        config.microsoft_client_id.clone(),
        config.microsoft_client_secret.clone(),
    ) {
        let redirect = format!("{}/oauth/federate/microsoft/callback", config.issuer);
        if let Ok(p) = MicrosoftProvider::new(
            &ms_id,
            &ms_sec,
            &redirect,
            config.microsoft_tenant.as_deref(),
        ) {
            idp_registry.register(Arc::new(p));
        }
    }

    let rp_id = config
        .webauthn_rp_id
        .clone()
        .unwrap_or_else(|| rp_id_from_issuer(&config.issuer));
    let webauthn = WebAuthnService::new(&rp_id, &config.issuer)
        .ok()
        .map(Arc::new);

    Ok(Arc::new(
        AppState::new(config, store, sessions, idp_registry, webauthn).await?,
    ))
}

pub async fn build_state_and_spawn_jobs(config: Config) -> anyhow::Result<Arc<AppState>> {
    let state = build_state(config).await?;
    spawn_archival_loop(state.as_ref().clone());
    Ok(state)
}

pub fn build_router(state: SharedState, metrics_handle: metrics_exporter_prometheus::PrometheusHandle) -> Router {
    if state.config.is_production() && state.config.allowed_origins.is_empty() {
        panic!("ALLOWED_ORIGINS must be set in production");
    }

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

    let metrics = Router::new()
        .route("/metrics", get(metrics))
        .layer(Extension(metrics_handle))
        .layer(axum_mw::from_fn_with_state(
            state.clone(),
            require_metrics_token,
        ));

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
        .route("/oauth/logout", get(logout_get).post(logout_post))
        .route("/oauth/device_authorization", post(device_authorization))
        .route("/login", get(login_page))
        .route("/admin", get(admin_page))
        .route("/admin/session", post(admin_create_session).delete(admin_delete_session).get(admin_session_status))
        .route("/device", get(device_page))
        .route("/device/approve", axum::routing::post(device_approve))
        .route("/oauth/mfa", post(complete_mfa))
        .route("/oauth/select-account", post(select_account))
        .route("/v1/portal", get(get_portal_from_map))
        .route("/v1/auth/magic-link/send", post(magic_link_send))
        .route("/v1/auth/magic-link/verify", get(magic_link_verify))
        .route("/v1/auth/email-otp/send", post(email_otp_send))
        .route("/v1/auth/email-otp/verify", post(email_otp_verify))
        .route("/v1/auth/phone-otp/send", post(phone_otp_send))
        .route("/v1/auth/phone-otp/verify", post(phone_otp_verify))
        .route("/v1/authz/check", post(check))
        .route("/oauth/federate/{provider}", get(federate_start))
        .route("/oauth/federate/{provider}/callback", get(federate_callback))
        .route("/saml/metadata", get(saml_metadata))
        .route("/saml/login", get(saml_login))
        .route("/saml/acs", post(saml_acs))
        .route("/saml/slo", get(saml_slo).post(saml_slo))
        .route("/saml/logout", get(saml_logout))
        .route("/saml/idp/metadata", get(idp_metadata))
        .route(
            "/saml/idp/sso",
            get(idp_sso_get).post(idp_sso_post),
        )
        .route("/saml/idp/login", post(idp_login))
        .route("/scim/v2/Users", get(scim_list_users).post(scim_create_user))
        .route(
            "/scim/v2/Users/{id}",
            get(scim_get_user)
                .patch(scim_patch_user)
                .delete(scim_delete_user),
        )
        .route("/scim/v2/Groups", get(scim_list_groups))
        .route(
            "/scim/v2/Groups/{id}",
            get(scim_get_group).patch(scim_patch_group),
        )
        .route("/v1/webauthn/login/begin", post(login_begin))
        .route("/v1/webauthn/login/finish", post(login_finish));

    let bootstrap = Router::new()
        .route("/v1/auth/register", post(register))
        .layer(axum_mw::from_fn_with_state(
            state.clone(),
            require_bootstrap_or_open,
        ));

    let authenticated = Router::new()
        .route("/v1/users/{id}/export", get(export_user))
        .route("/v1/users/{id}/privacy", axum::routing::delete(delete_user))
        .route("/v1/users/{id}/sessions", get(list_sessions))
        .route("/v1/users/{id}/sessions/revoke-all", post(revoke_all_sessions))
        .route("/v1/sessions/{id}", axum::routing::delete(revoke_session))
        .route("/v1/mfa/enroll", post(mfa_enroll))
        .route("/v1/mfa/verify", post(mfa_verify))
        .route("/v1/mfa/disable", post(mfa_disable))
        .route("/v1/webauthn/register/begin", post(register_begin))
        .route("/v1/webauthn/register/finish", post(register_finish))
        .layer(axum_mw::from_fn_with_state(state.clone(), require_authenticated));

    let admin = Router::new()
        .route("/v1/clients", post(create_client).get(list_clients))
        .route("/v1/clients/{id}", axum::routing::delete(delete_client))
        .route("/v1/accounts", post(create_account))
        .route("/v1/accounts/{id}", get(get_account))
        .route("/v1/websites", post(create_website))
        .route("/v1/roles", post(create_role))
        .route(
            "/v1/roles/{child_id}/inherit/{parent_id}",
            post(add_role_inheritance).delete(remove_role_inheritance),
        )
        .route("/v1/permissions", post(create_permission))
        .route("/v1/users/{id}/roles", post(assign_user_role))
        .route("/v1/api-keys", post(create_api_key_handler))
        .route("/v1/api-keys/{id}", axum::routing::delete(revoke_api_key_handler))
        .route("/v1/casbin/rules", post(create_casbin_rule))
        .route("/v1/casbin/rules/{id}", axum::routing::delete(delete_casbin_rule))
        .route("/v1/casbin/rules/account/{account_id}", get(list_casbin_rules))
        .route("/v1/webhooks", post(create_webhook))
        .route("/v1/idp-configs", get(list_idp_configs))
        .route("/v1/idp-configs/{provider}", post(upsert_idp_config).delete(delete_idp_config))
        .route("/v1/scim-tokens", post(create_scim_token_handler))
        .route("/v1/keys/rotate", post(admin_rotate_keys))
        .route("/v1/compliance/status", get(compliance_status))
        .route("/v1/users", get(search_users))
        .route("/v1/audit/events", get(list_audit_events))
        .route(
            "/v1/saml/service-providers",
            get(list_saml_sps).post(create_saml_sp),
        )
        .route(
            "/v1/saml/service-providers/{id}",
            axum::routing::delete(delete_saml_sp),
        )
        .layer(axum_mw::from_fn_with_state(state.clone(), require_admin));

    public
        .merge(metrics)
        .merge(bootstrap)
        .merge(authenticated)
        .merge(admin)
        .layer(axum_mw::from_fn_with_state(state.clone(), set_account_context))
        .layer(axum_mw::from_fn_with_state(state.clone(), security_headers))
        .layer(axum_mw::from_fn_with_state(state.clone(), ip_rate_limit))
        .layer(axum_mw::from_fn(request_metrics))
        .layer(cors)
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}
