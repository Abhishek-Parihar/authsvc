use axum::{
    extract::{Path, State},
    http::header::AUTHORIZATION,
    response::IntoResponse,
    Json,
};
use serde::Deserialize;
use serde_json::json;
use uuid::Uuid;

use crate::{
    handlers::{auth::extract_bearer_user, ApiError, AppResult, SharedState},
    services::{auth::validate_bearer_token, authz::authorize_user_access, privacy},
};

#[derive(Debug, Deserialize)]
pub struct PrivacyUserRequest {
    pub account_id: Option<String>,
}

pub async fn export_user(
    State(state): State<SharedState>,
    Path(user_id): Path<Uuid>,
    headers: axum::http::HeaderMap,
) -> AppResult<impl IntoResponse> {
    let (caller_id, account_id) = resolve_privacy_caller(&state, &headers).await?;
    authorize_user_access(&state, caller_id, account_id, user_id).await?;
    let (_, artifact) = privacy::request_export(&state, user_id, account_id).await?;
    Ok(Json(artifact))
}

pub async fn delete_user(
    State(state): State<SharedState>,
    Path(user_id): Path<Uuid>,
    headers: axum::http::HeaderMap,
) -> AppResult<impl IntoResponse> {
    let (caller_id, account_id) = resolve_privacy_caller(&state, &headers).await?;
    authorize_user_access(&state, caller_id, account_id, user_id).await?;
    privacy::delete_user(&state, user_id, account_id).await?;
    Ok(Json(json!({"deleted": true})))
}

async fn resolve_privacy_caller(
    state: &SharedState,
    headers: &axum::http::HeaderMap,
) -> Result<(Uuid, Uuid), ApiError> {
    if let Some(hdr) = headers.get(AUTHORIZATION).and_then(|v| v.to_str().ok()) {
        if let Some(token) = hdr.strip_prefix("Bearer ") {
            let is_bootstrap = state
                .config
                .bootstrap_secret
                .as_deref()
                .is_some_and(|secret| token == secret);
            if is_bootstrap {
                return Err(ApiError(authsvc_core::AuthError::Validation(
                    "user JWT required for privacy operations".into(),
                )));
            }
            let claims = validate_bearer_token(state, token).await?;
            let caller_id = Uuid::parse_str(&claims.sub)
                .map_err(|_| ApiError(authsvc_core::AuthError::InvalidToken))?;
            let account_id = Uuid::parse_str(&claims.account_id)
                .map_err(|_| ApiError(authsvc_core::AuthError::InvalidToken))?;
            if account_id == Uuid::nil() {
                return Err(ApiError(authsvc_core::AuthError::Validation(
                    "account_id required in access token".into(),
                )));
            }
            return Ok((caller_id, account_id));
        }
    }
    Err(ApiError(authsvc_core::AuthError::InvalidToken))
}
