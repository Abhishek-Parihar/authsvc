use authsvc_core::{AuthError, ClientRepository, SessionStore, UserRepository};
use chrono::{Duration, Utc};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::state::AppState;
use crate::crypto::password::generate_refresh_token;

pub async fn authorization_code_grant(
    state: &AppState,
    code: &str,
    redirect_uri: &str,
    code_verifier: &str,
    client_id: &str,
) -> Result<super::auth::TokenResponse, AuthError> {
    let consumed = state
        .store
        .consume_auth_code(code, redirect_uri, code_verifier)
        .await?
        .ok_or(AuthError::InvalidToken)?;

    let (user_id, client_uuid, _scopes) = consumed;
    let user = UserRepository::find_by_id(&state.store, user_id)
        .await?
        .ok_or(AuthError::UserNotFound)?;

    let client_row = ClientRepository::find_by_client_id(&state.store, client_id)
        .await?
        .ok_or(AuthError::ClientNotFound)?;
    if client_row.id != client_uuid {
        return Err(AuthError::InvalidToken);
    }

    super::auth::issue_user_tokens(state, &user, &client_row).await
}

pub async fn create_authorization_redirect(
    state: &AppState,
    client_id: &str,
    redirect_uri: &str,
    code_challenge: &str,
    scopes: &[String],
    user_id: Uuid,
) -> Result<String, AuthError> {
    let client = ClientRepository::find_by_client_id(&state.store, client_id)
        .await?
        .ok_or(AuthError::ClientNotFound)?;

    if !client.redirect_uris.is_empty() && !client.redirect_uris.contains(&redirect_uri.to_string())
    {
        return Err(AuthError::Validation("invalid redirect_uri".into()));
    }

    let code = generate_refresh_token();
    state
        .store
        .store_auth_code(
            &code,
            client.id,
            user_id,
            redirect_uri,
            code_challenge,
            scopes,
            Utc::now() + Duration::minutes(5),
        )
        .await?;

    Ok(format!(
        "{redirect_uri}?code={code}&state={}",
        Uuid::new_v4()
    ))
}

pub async fn store_browser_session(state: &AppState, user_id: Uuid) -> Result<Uuid, AuthError> {
    let session_id = Uuid::new_v4();
    SessionStore::create(
        &state.sessions,
        session_id,
        user_id,
        state.config.session_ttl_secs,
    )
    .await?;
    Ok(session_id)
}

pub fn pkce_challenge(verifier: &str) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}
