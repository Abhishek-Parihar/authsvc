use axum::{
    extract::State,
    http::{header::AUTHORIZATION, StatusCode},
    response::IntoResponse,
    Json,
};
use authsvc_core::AuthError;
use base64::Engine;
use serde::Deserialize;
use serde_json::json;

use crate::{
    handlers::{ApiError, AppResult, SharedState},
    services::{
        auth::{
            client_credentials_grant, create_oauth_client, password_login, refresh_token_grant,
            register_user, revoke_refresh_token, validate_bearer_token,
        },
        api_keys::api_key_grant,
        authz::complete_mfa_login,
        mfa::{disable_mfa, enroll_totp, send_magic_link, verify_magic_link},
        oidc_flow::authorization_code_grant,
    },
};

#[derive(Debug, Deserialize)]
pub struct RegisterRequest {
    pub email: String,
    pub password: String,
    pub display_name: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct CreateClientRequest {
    pub name: String,
    pub redirect_uris: Option<Vec<String>>,
}

pub async fn register(
    State(state): State<SharedState>,
    Json(body): Json<RegisterRequest>,
) -> AppResult<impl IntoResponse> {
    state
        .rate_limiter
        .check(&format!("register:{}", body.email))
        .await?;
    let user = register_user(&state, &body.email, &body.password, body.display_name).await?;
    Ok(Json(json!({
        "id": user.id,
        "email": user.email,
        "tenant_id": user.tenant_id
    })))
}

pub async fn create_client(
    State(state): State<SharedState>,
    Json(body): Json<CreateClientRequest>,
) -> AppResult<impl IntoResponse> {
    let (client, secret) = create_oauth_client(
        &state,
        &body.name,
        body.redirect_uris.unwrap_or_default(),
    )
    .await?;
    Ok(Json(json!({
        "client_id": client.client_id,
        "client_secret": secret,
        "grant_types": client.grant_types,
        "scopes": client.scopes
    })))
}

#[derive(Debug, Deserialize)]
pub struct TokenRequest {
    pub grant_type: String,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub username: Option<String>,
    pub password: Option<String>,
    pub refresh_token: Option<String>,
    pub code: Option<String>,
    pub redirect_uri: Option<String>,
    pub code_verifier: Option<String>,
    pub api_key: Option<String>,
}

pub async fn token(
    State(state): State<SharedState>,
    headers: axum::http::HeaderMap,
    body: Option<Json<TokenRequest>>,
) -> AppResult<impl IntoResponse> {
    let mut req = body.map(|j| j.0).unwrap_or(TokenRequest {
        grant_type: String::new(),
        client_id: None,
        client_secret: None,
        username: None,
        password: None,
        refresh_token: None,
        code: None,
        redirect_uri: None,
        code_verifier: None,
        api_key: None,
    });

    if let Some(auth) = headers.get(AUTHORIZATION).and_then(|v| v.to_str().ok()) {
        if let Some(encoded) = auth.strip_prefix("Basic ") {
            if let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(encoded) {
                if let Ok(pair) = String::from_utf8(decoded) {
                    if let Some((id, secret)) = pair.split_once(':') {
                        req.client_id = Some(id.to_string());
                        req.client_secret = Some(secret.to_string());
                    }
                }
            }
        }
    }

    match req.grant_type.as_str() {
        "password" => {
            let client_id = req.client_id.ok_or_else(|| {
                ApiError(AuthError::Validation("client_id required".into()))
            })?;
            let username = req.username.ok_or_else(|| {
                ApiError(AuthError::Validation("username required".into()))
            })?;
            let password = req.password.ok_or_else(|| {
                ApiError(AuthError::Validation("password required".into()))
            })?;
            let tokens = password_login(&state, &username, &password, &client_id, None).await?;
            Ok(Json(tokens))
        }
        "client_credentials" => {
            let client_id = req.client_id.ok_or_else(|| {
                ApiError(AuthError::Validation("client_id required".into()))
            })?;
            let client_secret = req.client_secret.ok_or_else(|| {
                ApiError(AuthError::Validation("client_secret required".into()))
            })?;
            let tokens =
                client_credentials_grant(&state, &client_id, &client_secret).await?;
            Ok(Json(tokens))
        }
        "refresh_token" => {
            let client_id = req.client_id.ok_or_else(|| {
                ApiError(AuthError::Validation("client_id required".into()))
            })?;
            let refresh_token = req.refresh_token.ok_or_else(|| {
                ApiError(AuthError::Validation("refresh_token required".into()))
            })?;
            let tokens = refresh_token_grant(&state, &refresh_token, &client_id).await?;
            Ok(Json(tokens))
        }
        "authorization_code" => {
            let client_id = req.client_id.ok_or_else(|| {
                ApiError(AuthError::Validation("client_id required".into()))
            })?;
            let code = req
                .code
                .ok_or_else(|| ApiError(AuthError::Validation("code required".into())))?;
            let redirect_uri = req.redirect_uri.ok_or_else(|| {
                ApiError(AuthError::Validation("redirect_uri required".into()))
            })?;
            let code_verifier = req.code_verifier.ok_or_else(|| {
                ApiError(AuthError::Validation("code_verifier required".into()))
            })?;
            let tokens = authorization_code_grant(
                &state,
                &code,
                &redirect_uri,
                &code_verifier,
                &client_id,
            )
            .await?;
            Ok(Json(tokens))
        }
        "api_key" => {
            let api_key = req.api_key.ok_or_else(|| {
                ApiError(AuthError::Validation("api_key required".into()))
            })?;
            let tokens = api_key_grant(&state, &api_key).await?;
            Ok(Json(tokens))
        }
        other => Err(ApiError(AuthError::UnsupportedGrantType(other.into()))),
    }
}

#[derive(Debug, Deserialize)]
pub struct RevokeRequest {
    pub token: String,
}

pub async fn revoke(
    State(state): State<SharedState>,
    Json(body): Json<RevokeRequest>,
) -> AppResult<impl IntoResponse> {
    revoke_refresh_token(&state, &body.token).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Debug, Deserialize)]
pub struct MfaCompleteRequest {
    pub challenge_id: String,
    pub code: String,
}

pub async fn complete_mfa(
    State(state): State<SharedState>,
    Json(body): Json<MfaCompleteRequest>,
) -> AppResult<impl IntoResponse> {
    let challenge_id = uuid::Uuid::parse_str(&body.challenge_id)
        .map_err(|_| ApiError(AuthError::Validation("invalid challenge_id".into())))?;
    let tokens = complete_mfa_login(&state, challenge_id, &body.code).await?;
    Ok(Json(tokens))
}

#[derive(Debug, Deserialize)]
pub struct MfaEnrollRequest {
    pub user_id: String,
}

pub async fn mfa_enroll(
    State(state): State<SharedState>,
    Json(body): Json<MfaEnrollRequest>,
) -> AppResult<impl IntoResponse> {
    let user_id = uuid::Uuid::parse_str(&body.user_id)
        .map_err(|_| ApiError(AuthError::Validation("invalid user_id".into())))?;
    let (url, recovery) = enroll_totp(&state, user_id).await?;
    Ok(Json(json!({"otpauth_url": url, "recovery_codes": recovery})))
}

#[derive(Debug, Deserialize)]
pub struct MfaVerifyRequest {
    pub user_id: String,
    pub code: String,
}

pub async fn mfa_verify(
    State(state): State<SharedState>,
    Json(body): Json<MfaVerifyRequest>,
) -> AppResult<impl IntoResponse> {
    let user_id = uuid::Uuid::parse_str(&body.user_id)
        .map_err(|_| ApiError(AuthError::Validation("invalid user_id".into())))?;
    crate::services::mfa::verify_totp(&state, user_id, &body.code).await?;
    Ok(Json(json!({"verified": true})))
}

pub async fn mfa_disable(
    State(state): State<SharedState>,
    Json(body): Json<MfaEnrollRequest>,
) -> AppResult<impl IntoResponse> {
    let user_id = uuid::Uuid::parse_str(&body.user_id)
        .map_err(|_| ApiError(AuthError::Validation("invalid user_id".into())))?;
    disable_mfa(&state, user_id).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Debug, Deserialize)]
pub struct MagicLinkSendRequest {
    pub email: String,
}

pub async fn magic_link_send(
    State(state): State<SharedState>,
    Json(body): Json<MagicLinkSendRequest>,
) -> AppResult<impl IntoResponse> {
    let link = send_magic_link(&state, &body.email).await?;
    Ok(Json(json!({"sent": true, "dev_link": link})))
}

pub async fn magic_link_verify(
    State(state): State<SharedState>,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> AppResult<impl IntoResponse> {
    let token = params
        .get("token")
        .ok_or_else(|| ApiError(AuthError::Validation("token required".into())))?;
    let client_id = params
        .get("client_id")
        .ok_or_else(|| ApiError(AuthError::Validation("client_id required".into())))?;
    let tokens = verify_magic_link(&state, token, client_id).await?;
    Ok(Json(tokens))
}

pub async fn extract_bearer_user(
    state: &SharedState,
    headers: &axum::http::HeaderMap,
) -> Result<crate::crypto::jwt::AccessTokenClaims, ApiError> {
    let hdr = headers
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or(ApiError(AuthError::InvalidToken))?;
    let token = hdr
        .strip_prefix("Bearer ")
        .ok_or(ApiError(AuthError::InvalidToken))?;
    Ok(validate_bearer_token(state, token).await?)
}
