use axum::http::{header::AUTHORIZATION, HeaderMap};
use authsvc_core::AuthError;
use uuid::Uuid;

use crate::{
    crypto::jwt::AccessTokenClaims,
    handlers::SharedState,
    services::{api_keys::validate_api_key, auth::validate_bearer_token},
};

#[derive(Debug, Clone)]
pub enum AuthContext {
    UserJwt(AccessTokenClaims),
    ApiKey {
        key_id: Uuid,
        tenant_id: Uuid,
        scopes: Vec<String>,
    },
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
        let (key_id, tenant_id, scopes) = validate_api_key(state, &key).await?;
        return Ok(AuthContext::ApiKey {
            key_id,
            tenant_id,
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
