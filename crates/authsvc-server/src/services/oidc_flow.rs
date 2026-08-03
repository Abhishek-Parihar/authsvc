use authsvc_core::{AccountOption, AuthError, SessionStore};
use chrono::{Duration, Utc};
use serde::Serialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::{auth, login_selection, state::AppState};
use crate::crypto::{jwt::AccessTokenClaims, password::generate_refresh_token};

pub struct AuthorizeParams {
    pub client_id: String,
    pub redirect_uri: String,
    pub code_challenge: String,
    pub scopes: Vec<String>,
}

pub async fn start_authorization(
    state: &AppState,
    params: AuthorizeParams,
) -> Result<String, AuthError> {
    let client = state
        .repos
        .clients()
        .find_by_client_id(&params.client_id)
        .await?
        .ok_or(AuthError::ClientNotFound)?;

    crate::security::redirect_uri::validate_redirect_uri(
        &client,
        &params.redirect_uri,
        state.config.is_production(),
        state.config.allow_custom_scheme_redirects,
    )?;

    let login_state = Uuid::new_v4().to_string();
    state
        .repos
        .oidc()
        .store_login_state(
            &login_state,
            &params.client_id,
            &params.redirect_uri,
            &params.code_challenge,
            &params.scopes,
            Utc::now() + Duration::minutes(10),
        )
        .await?;

    Ok(login_state)
}

pub async fn userinfo(state: &AppState, claims: &AccessTokenClaims) -> Result<Value, AuthError> {
    let user_id = Uuid::parse_str(&claims.sub).map_err(|_| AuthError::InvalidToken)?;
    let user = super::cache_layer::cached_user(state, user_id).await?;
    let display_name = resolve_display_name(state, &user, claims).await?;
    Ok(json!({
        "sub": user.id,
        "email": user.email,
        "email_verified": user.email_verified,
        "name": display_name,
        "account_id": claims.account_id,
        "website_id": claims.website_id
    }))
}

async fn resolve_display_name(
    state: &AppState,
    user: &authsvc_core::User,
    claims: &AccessTokenClaims,
) -> Result<Option<String>, AuthError> {
    if let Some(wid) = claims
        .website_id
        .as_ref()
        .and_then(|s| Uuid::parse_str(s).ok())
    {
        if let Some((name, _, _)) = state.repos.postgres().get_user_profile(user.id, wid).await? {
            if name.is_some() {
                return Ok(name);
            }
        }
    }
    Ok(user.display_name.clone())
}

#[derive(Debug, Serialize)]
pub struct BrowserLoginSuccess {
    pub redirect: String,
    pub session_id: Uuid,
}

#[derive(Debug, Serialize)]
pub struct BrowserLoginMfa {
    pub mfa_required: bool,
    pub mfa_challenge_id: String,
}

#[derive(Debug, Serialize)]
pub struct BrowserLoginAccountSelection {
    pub account_selection_required: bool,
    pub selection_id: String,
    pub accounts: Vec<AccountOption>,
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum BrowserLoginResult {
    Success(BrowserLoginSuccess),
    MfaRequired(BrowserLoginMfa),
    AccountSelection(BrowserLoginAccountSelection),
}

pub async fn complete_browser_login(
    state: &AppState,
    login_state: &str,
    email: &str,
    password: &str,
    ip: Option<&str>,
) -> Result<BrowserLoginResult, AuthError> {
    let login = state
        .repos
        .oidc()
        .get_login_state(login_state)
        .await?
        .ok_or(AuthError::InvalidToken)?;

    let (client_id, redirect_uri, code_challenge, scopes) = login;
    let user = auth::verify_user_password(state, email, password, ip).await?;

    let client = state
        .repos
        .clients()
        .find_by_client_id(&client_id)
        .await?
        .ok_or(AuthError::ClientNotFound)?;

    if user.mfa_enabled {
        let challenge_id = Uuid::new_v4();
        state
            .repos
            .mfa()
            .store_mfa_challenge(
                challenge_id,
                user.id,
                client.id,
                Utc::now() + Duration::minutes(5),
            )
            .await?;
        return Ok(BrowserLoginResult::MfaRequired(BrowserLoginMfa {
            mfa_required: true,
            mfa_challenge_id: challenge_id.to_string(),
        }));
    }

    let options = login_selection::list_account_options(state, user.id).await?;
    let active: Vec<_> = options
        .into_iter()
        .filter(|a| a.status == "active")
        .collect();

    if active.len() > 1 {
        let selection_id =
            login_selection::create_login_selection(state, user.id, &client.client_id).await?;
        return Ok(BrowserLoginResult::AccountSelection(
            BrowserLoginAccountSelection {
                account_selection_required: true,
                selection_id: selection_id.to_string(),
                accounts: active,
            },
        ));
    }

    let session_id = store_browser_session(state, user.id).await?;
    let redirect = create_authorization_redirect(
        state,
        &client_id,
        &redirect_uri,
        &code_challenge,
        &scopes,
        user.id,
    )
    .await?;

    Ok(BrowserLoginResult::Success(BrowserLoginSuccess {
        redirect,
        session_id,
    }))
}

pub async fn authorization_code_grant(
    state: &AppState,
    code: &str,
    redirect_uri: &str,
    code_verifier: &str,
    client_id: &str,
) -> Result<super::auth::TokenResponse, AuthError> {
    let consumed = state
        .repos
        .oidc()
        .consume_auth_code(code, redirect_uri, code_verifier)
        .await?
        .ok_or(AuthError::InvalidToken)?;

    let (user_id, client_uuid, _scopes) = consumed;
    let user = state
        .repos
        .users()
        .find_by_id(user_id)
        .await?
        .ok_or(AuthError::UserNotFound)?;

    let client_row = state
        .repos
        .clients()
        .find_by_client_id(client_id)
        .await?
        .ok_or(AuthError::ClientNotFound)?;
    if client_row.id != client_uuid {
        return Err(AuthError::InvalidToken);
    }

    super::auth::complete_login(state, &user, &client_row).await
}

pub async fn create_authorization_redirect(
    state: &AppState,
    client_id: &str,
    redirect_uri: &str,
    code_challenge: &str,
    scopes: &[String],
    user_id: Uuid,
) -> Result<String, AuthError> {
    let client = state
        .repos
        .clients()
        .find_by_client_id(client_id)
        .await?
        .ok_or(AuthError::ClientNotFound)?;

    crate::security::redirect_uri::validate_redirect_uri(
        &client,
        redirect_uri,
        state.config.is_production(),
        state.config.allow_custom_scheme_redirects,
    )?;

    let code = generate_refresh_token();
    state
        .repos
        .oidc()
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
