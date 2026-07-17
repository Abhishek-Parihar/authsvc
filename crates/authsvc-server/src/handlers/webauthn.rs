use axum::{extract::State, Json};
use serde::Deserialize;
use serde_json::json;
use uuid::Uuid;
use webauthn_rs::prelude::{PublicKeyCredential, RegisterPublicKeyCredential};

use crate::{
    handlers::{ApiError, AppResult, SharedState},
};
use authsvc_core::AuthError;

#[derive(Debug, Deserialize)]
pub struct WebAuthnRegisterBeginRequest {
    pub user_id: String,
    pub name: Option<String>,
}

pub async fn register_begin(
    State(state): State<SharedState>,
    Json(body): Json<WebAuthnRegisterBeginRequest>,
) -> AppResult<impl axum::response::IntoResponse> {
    let user_id = Uuid::parse_str(&body.user_id)
        .map_err(|_| ApiError(AuthError::Validation("invalid user_id".into())))?;
    let webauthn = state.webauthn.as_ref().ok_or_else(|| {
        ApiError(AuthError::Internal("webauthn not configured".into()))
    })?;
    let (challenge_id, ccr) = webauthn
        .begin_registration(state.as_ref(), user_id, body.name)
        .await?;
    Ok(Json(json!({
        "challenge_id": challenge_id,
        "options": ccr,
        "rp_origin": webauthn.origin()
    })))
}

#[derive(Debug, Deserialize)]
pub struct WebAuthnRegisterFinishRequest {
    pub challenge_id: String,
    pub credential: RegisterPublicKeyCredential,
}

pub async fn register_finish(
    State(state): State<SharedState>,
    Json(body): Json<WebAuthnRegisterFinishRequest>,
) -> AppResult<impl axum::response::IntoResponse> {
    let challenge_id = Uuid::parse_str(&body.challenge_id)
        .map_err(|_| ApiError(AuthError::Validation("invalid challenge_id".into())))?;
    let webauthn = state.webauthn.as_ref().ok_or_else(|| {
        ApiError(AuthError::Internal("webauthn not configured".into()))
    })?;
    let credential_id = webauthn
        .finish_registration(state.as_ref(), challenge_id, body.credential)
        .await?;
    Ok(Json(json!({"credential_id": credential_id, "registered": true})))
}

#[derive(Debug, Deserialize)]
pub struct WebAuthnLoginBeginRequest {
    pub email: String,
    pub client_id: String,
}

pub async fn login_begin(
    State(state): State<SharedState>,
    Json(body): Json<WebAuthnLoginBeginRequest>,
) -> AppResult<impl axum::response::IntoResponse> {
    let webauthn = state.webauthn.as_ref().ok_or_else(|| {
        ApiError(AuthError::Internal("webauthn not configured".into()))
    })?;
    let (challenge_id, rcr) = webauthn
        .begin_login(state.as_ref(), &body.email, &body.client_id)
        .await?;
    Ok(Json(json!({
        "challenge_id": challenge_id,
        "options": rcr,
        "rp_origin": webauthn.origin()
    })))
}

#[derive(Debug, Deserialize)]
pub struct WebAuthnLoginFinishRequest {
    pub challenge_id: String,
    pub credential: PublicKeyCredential,
}

pub async fn login_finish(
    State(state): State<SharedState>,
    Json(body): Json<WebAuthnLoginFinishRequest>,
) -> AppResult<impl axum::response::IntoResponse> {
    let challenge_id = Uuid::parse_str(&body.challenge_id)
        .map_err(|_| ApiError(AuthError::Validation("invalid challenge_id".into())))?;
    let webauthn = state.webauthn.as_ref().ok_or_else(|| {
        ApiError(AuthError::Internal("webauthn not configured".into()))
    })?;
    let tokens = webauthn
        .finish_login(state.as_ref(), challenge_id, body.credential)
        .await?;
    Ok(Json(tokens))
}
