use axum::http::{header::AUTHORIZATION, HeaderMap};
use authsvc_core::AuthError;
use base64::Engine;
use uuid::Uuid;

use crate::{
    config::Config,
    handlers::SharedState,
    services::{api_keys::validate_api_key, auth::validate_bearer_token, authz::user_has_admin_permission},
};

#[derive(Debug, Clone)]
pub enum AuthContext {
    UserJwt(crate::crypto::jwt::AccessTokenClaims),
    ApiKey {
        key_id: Uuid,
        account_id: Uuid,
        scopes: Vec<String>,
    },
}

#[derive(Debug, Clone)]
pub struct ClientCredentials {
    pub client_id: String,
    pub client_secret: String,
}

pub fn extract_api_key(headers: &HeaderMap) -> Option<String> {
    if let Some(hdr) = headers.get(AUTHORIZATION).and_then(|v| v.to_str().ok()) {
        if let Some(key) = hdr.strip_prefix("ApiKey ") {
            return Some(key.trim().to_string());
        }
    }
    headers
        .get("x-api-key")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .map(str::to_string)
}

pub fn extract_client_credentials(
    headers: &HeaderMap,
    client_id: Option<String>,
    client_secret: Option<String>,
) -> Result<ClientCredentials, AuthError> {
    let mut id = client_id;
    let mut secret = client_secret;

    if let Some(auth) = headers.get(AUTHORIZATION).and_then(|v| v.to_str().ok()) {
        if let Some(encoded) = auth.strip_prefix("Basic ") {
            if let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(encoded) {
                if let Ok(pair) = String::from_utf8(decoded) {
                    if let Some((cid, csec)) = pair.split_once(':') {
                        id = Some(cid.to_string());
                        secret = Some(csec.to_string());
                    }
                }
            }
        }
    }

    match (id, secret) {
        (Some(client_id), Some(client_secret)) if !client_id.is_empty() && !client_secret.is_empty() => {
            Ok(ClientCredentials {
                client_id,
                client_secret,
            })
        }
        _ => Err(AuthError::InvalidClientCredentials),
    }
}

pub fn bootstrap_token_matches(config: &Config, token: &str) -> bool {
    let Some(secret) = &config.bootstrap_secret else {
        return false;
    };
    if config.is_production() && !config.allow_bootstrap_secret {
        return false;
    }
    crate::crypto::constant_time::secure_compare(token.trim(), secret)
}

pub fn bootstrap_authorized(state: &SharedState, headers: &HeaderMap) -> bool {
    headers
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|hdr| {
            hdr.strip_prefix("Bearer ")
                .is_some_and(|token| bootstrap_token_matches(&state.config, token))
        })
}

pub async fn authenticate(
    state: &SharedState,
    headers: &HeaderMap,
) -> Result<AuthContext, AuthError> {
    if let Some(hdr) = headers.get(AUTHORIZATION).and_then(|v| v.to_str().ok()) {
        if let Some(token) = hdr.strip_prefix("Bearer ") {
            let claims = validate_bearer_token(state, token).await?;
            return Ok(AuthContext::UserJwt(claims));
        }
    }

    if let Some(key) = extract_api_key(headers) {
        let (key_id, account_id, scopes) = validate_api_key(state, &key).await?;
        return Ok(AuthContext::ApiKey {
            key_id,
            account_id,
            scopes,
        });
    }

    Err(AuthError::InvalidToken)
}

pub fn api_key_has_scope(scopes: &[String], required: &str) -> bool {
    scopes.iter().any(|s| s == "*" || s == required)
}

pub fn api_key_has_admin(scopes: &[String]) -> bool {
    api_key_has_scope(scopes, "admin")
}

pub async fn authorize_authz_caller(
    state: &SharedState,
    headers: &HeaderMap,
    account_id: Uuid,
    subject_id: Uuid,
) -> Result<(), AuthError> {
    state
        .rate_limiter
        .check_with_limit(
            &format!("authz:{account_id}"),
            account_rate_limit(state, account_id).await?,
        )
        .await?;

    if bootstrap_authorized(state, headers) {
        return Ok(());
    }

    match authenticate(state, headers).await {
        Ok(AuthContext::ApiKey {
            account_id: key_account,
            scopes,
            ..
        }) => {
            if key_account != account_id {
                return Err(AuthError::Forbidden);
            }
            if api_key_has_scope(&scopes, "authz") || api_key_has_admin(&scopes) {
                return Ok(());
            }
            Err(AuthError::Forbidden)
        }
        Ok(AuthContext::UserJwt(claims)) => {
            let caller_id = Uuid::parse_str(&claims.sub)
                .map_err(|_| AuthError::InvalidToken)?;
            let caller_account = Uuid::parse_str(&claims.account_id)
                .map_err(|_| AuthError::InvalidToken)?;
            if caller_account != account_id {
                return Err(AuthError::Forbidden);
            }
            if caller_id == subject_id {
                return Ok(());
            }
            if user_has_admin_permission(state.as_ref(), caller_id, account_id).await? {
                return Ok(());
            }
            Err(AuthError::Forbidden)
        }
        Err(_) => Err(AuthError::InvalidToken),
    }
}

async fn account_rate_limit(
    state: &SharedState,
    account_id: Uuid,
) -> Result<u32, AuthError> {
    if let Some(override_limit) = state
        .repos
        .postgres()
        .account_rate_limit_override(account_id)
        .await?
    {
        if override_limit > 0 {
            return Ok(override_limit as u32);
        }
    }
    Ok(state.config.rate_limit_per_minute)
}
