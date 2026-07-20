use axum::{
    extract::{Path, State},
    response::IntoResponse,
    Json,
};
use serde::Deserialize;
use serde_json::json;
use uuid::Uuid;

use crate::{
    handlers::{auth::extract_bearer_user, ApiError, AppResult, SharedState},
    services::{admin::default_account_id, privacy},
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
    let claims = extract_bearer_user(&state, &headers).await?;
    let account_id = resolve_account_id(&state, &claims.account_id, None).await?;
    let (_, artifact) = privacy::request_export(&state, user_id, account_id).await?;
    Ok(Json(artifact))
}

pub async fn delete_user(
    State(state): State<SharedState>,
    Path(user_id): Path<Uuid>,
    headers: axum::http::HeaderMap,
) -> AppResult<impl IntoResponse> {
    let claims = extract_bearer_user(&state, &headers).await?;
    let account_id = resolve_account_id(&state, &claims.account_id, None).await?;
    privacy::delete_user(&state, user_id, account_id).await?;
    Ok(Json(json!({"deleted": true})))
}

async fn resolve_account_id(
    state: &SharedState,
    from_claims: &str,
    override_id: Option<&str>,
) -> Result<Uuid, ApiError> {
    if let Some(id) = override_id {
        return Uuid::parse_str(id)
            .map_err(|_| ApiError(authsvc_core::AuthError::Validation("invalid account_id".into())));
    }
    if let Ok(id) = Uuid::parse_str(from_claims) {
        if id != Uuid::nil() {
            return Ok(id);
        }
    }
    Ok(default_account_id(state).await?)
}
