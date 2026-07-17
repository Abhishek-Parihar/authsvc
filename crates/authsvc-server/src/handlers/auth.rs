use axum::{extract::State, Json};
use serde::Deserialize;
use serde_json::json;

use crate::{
    handlers::{ApiError, AppResult, SharedState},
    services::auth::{client_credentials_grant, create_oauth_client, password_login, refresh_token_grant, register_user, revoke_refresh_token},
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
}

pub async fn register(
    State(state): State<SharedState>,
    Json(body): Json<RegisterRequest>,
) -> AppResult<impl axum::response::IntoResponse> {
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
) -> AppResult<impl axum::response::IntoResponse> {
    let (client, secret) = create_oauth_client(&state, &body.name).await?;
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
    pub scope: Option<String>,
}

pub async fn token(
    State(state): State<SharedState>,
    Json(body): Json<TokenRequest>,
) -> AppResult<impl axum::response::IntoResponse> {
    match body.grant_type.as_str() {
        "password" => {
            let client_id = body
                .client_id
                .ok_or_else(|| ApiError(AuthError::Validation("client_id required".into())))?;
            let username = body
                .username
                .ok_or_else(|| ApiError(AuthError::Validation("username required".into())))?;
            let password = body
                .password
                .ok_or_else(|| ApiError(AuthError::Validation("password required".into())))?;
            let tokens = password_login(&state, &username, &password, &client_id).await?;
            Ok(Json(tokens))
        }
        "client_credentials" => {
            let client_id = body
                .client_id
                .ok_or_else(|| ApiError(AuthError::Validation("client_id required".into())))?;
            let client_secret = body
                .client_secret
                .ok_or_else(|| ApiError(AuthError::Validation("client_secret required".into())))?;
            let tokens = client_credentials_grant(&state, &client_id, &client_secret).await?;
            Ok(Json(tokens))
        }
        "refresh_token" => {
            let client_id = body
                .client_id
                .ok_or_else(|| ApiError(AuthError::Validation("client_id required".into())))?;
            let refresh_token = body
                .refresh_token
                .ok_or_else(|| ApiError(AuthError::Validation("refresh_token required".into())))?;
            let tokens = refresh_token_grant(&state, &refresh_token, &client_id).await?;
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
) -> AppResult<impl axum::response::IntoResponse> {
    revoke_refresh_token(&state, &body.token).await?;
    Ok(axum::http::StatusCode::NO_CONTENT)
}

use authsvc_core::AuthError;
