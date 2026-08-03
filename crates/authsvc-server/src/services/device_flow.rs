use authsvc_core::AuthError;
use chrono::{Duration, Utc};
use rand::Rng;
use serde::Serialize;
use uuid::Uuid;

use super::{auth, state::AppState};
use crate::crypto::password::{generate_refresh_token, hash_token};

const DEVICE_CODE_TTL_SECS: i64 = 600;
const POLL_INTERVAL_SECS: u64 = 5;

#[derive(Debug, Serialize)]
pub struct DeviceAuthorizationResponse {
    pub device_code: String,
    pub user_code: String,
    pub verification_uri: String,
    pub verification_uri_complete: String,
    pub expires_in: u64,
    pub interval: u64,
}

pub async fn start_device_authorization(
    state: &AppState,
    client_id: &str,
    client_secret: &str,
    scope: Option<&str>,
) -> Result<DeviceAuthorizationResponse, AuthError> {
    state
        .rate_limiter
        .check(&format!("device:{client_id}"))
        .await?;

    let client = auth::verify_confidential_client(state, client_id, client_secret).await?;

    let scopes: Vec<String> = scope
        .unwrap_or("openid profile email")
        .split_whitespace()
        .map(str::to_string)
        .collect();

    let device_code = generate_refresh_token();
    let device_hash = hash_token(&device_code);
    let user_code = generate_user_code();

    state
        .repos
        .postgres()
        .store_device_code(
            &device_hash,
            &user_code,
            client.id,
            &scopes,
            Utc::now() + Duration::seconds(DEVICE_CODE_TTL_SECS),
        )
        .await?;

    let issuer = &state.config.issuer;
    Ok(DeviceAuthorizationResponse {
        device_code,
        user_code: user_code.clone(),
        verification_uri: format!("{issuer}/device"),
        verification_uri_complete: format!("{issuer}/device?user_code={user_code}"),
        expires_in: DEVICE_CODE_TTL_SECS as u64,
        interval: POLL_INTERVAL_SECS,
    })
}

pub async fn approve_device_code(
    state: &AppState,
    user_code: &str,
    email: &str,
    password: &str,
    ip: Option<&str>,
) -> Result<(), AuthError> {
    let user = auth::verify_user_password(state, email, password, ip).await?;
    state
        .repos
        .postgres()
        .approve_device_code(user_code, user.id)
        .await?
        .ok_or(AuthError::InvalidToken)?;
    Ok(())
}

pub async fn device_code_grant(
    state: &AppState,
    client_id: &str,
    device_code: &str,
) -> Result<auth::TokenResponse, AuthError> {
    let device_hash = hash_token(device_code);
    let record = state
        .repos
        .postgres()
        .get_device_code(&device_hash)
        .await?
        .ok_or(AuthError::InvalidToken)?;

    if record.expires_at < Utc::now() {
        state
            .repos
            .postgres()
            .delete_device_code(&device_hash)
            .await?;
        return Err(AuthError::InvalidToken);
    }

    if !record.approved {
        return Err(AuthError::AuthorizationPending);
    }

    let user_id = record.user_id.ok_or(AuthError::InvalidToken)?;
    let client = state
        .repos
        .clients()
        .find_by_client_id(client_id)
        .await?
        .ok_or(AuthError::ClientNotFound)?;

    if client.id != record.client_id {
        return Err(AuthError::InvalidClientCredentials);
    }

    let user = state
        .repos
        .users()
        .find_by_id(user_id)
        .await?
        .ok_or(AuthError::UserNotFound)?;

    state
        .repos
        .postgres()
        .delete_device_code(&device_hash)
        .await?;

    auth::complete_login(state, &user, &client).await
}

fn generate_user_code() -> String {
    const CHARSET: &[u8] = b"BCDFGHJKLMNPQRSTVWXZ";
    let mut rng = rand::thread_rng();
    let chars: String = (0..8)
        .map(|_| CHARSET[rng.gen_range(0..CHARSET.len())] as char)
        .collect();
    format!("{}-{}", &chars[..4], &chars[4..])
}
