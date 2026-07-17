use authsvc_core::AuthError;
use uuid::Uuid;

use super::state::AppState;
use crate::crypto::password::{generate_refresh_token, hash_token};

pub async fn create_api_key(
    state: &AppState,
    tenant_id: Uuid,
    name: &str,
    scopes: Vec<String>,
) -> Result<(Uuid, String), AuthError> {
    let plain = format!("ak_{}", generate_refresh_token());
    let prefix: String = plain.chars().take(12).collect();
    let hash = hash_token(&plain);
    let id = state
        .store
        .create_api_key(tenant_id, name, &prefix, &hash, &scopes, None)
        .await?;
    Ok((id, plain))
}

pub async fn validate_api_key(state: &AppState, key: &str) -> Result<(Uuid, Uuid, Vec<String>), AuthError> {
    let hash = hash_token(key);
    state
        .store
        .find_api_key(&hash)
        .await?
        .ok_or(AuthError::InvalidCredentials)
}

pub async fn api_key_grant(state: &AppState, api_key: &str) -> Result<super::auth::TokenResponse, AuthError> {
    let (key_id, tenant_id, scopes) = validate_api_key(state, api_key).await?;
    let (access_token, _) = state.jwt.issue_access_token(
        key_id,
        tenant_id,
        Some(&format!("apikey:{key_id}")),
        &scopes,
    )?;

    Ok(super::auth::TokenResponse {
        access_token,
        token_type: "Bearer".into(),
        expires_in: state.jwt.access_ttl_secs(),
        refresh_token: None,
        scope: scopes.join(" "),
        id_token: None,
        mfa_required: None,
        mfa_challenge_id: None,
    })
}

pub async fn revoke_api_key(state: &AppState, id: Uuid) -> Result<(), AuthError> {
    state.store.revoke_api_key(id).await
}
