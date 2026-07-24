use axum::{
    extract::{Path, State},
    response::IntoResponse,
    Json,
};
use serde_json::json;
use uuid::Uuid;

use crate::{
    handlers::{auth::extract_bearer_user, AppResult, SharedState},
    services::{authz::authorize_user_access, sessions},
};

pub async fn list_sessions(
    State(state): State<SharedState>,
    Path(user_id): Path<Uuid>,
    headers: axum::http::HeaderMap,
) -> AppResult<impl IntoResponse> {
    let claims = extract_bearer_user(&state, &headers).await?;
    let caller_id = Uuid::parse_str(&claims.sub).map_err(|_| {
        crate::handlers::ApiError(authsvc_core::AuthError::InvalidToken)
    })?;
    let account_id = Uuid::parse_str(&claims.account_id).map_err(|_| {
        crate::handlers::ApiError(authsvc_core::AuthError::InvalidToken)
    })?;
    authorize_user_access(&state, caller_id, account_id, user_id).await?;
    let sessions = sessions::list_sessions(&state, user_id).await?;
    Ok(Json(json!({"sessions": sessions})))
}

pub async fn revoke_session(
    State(state): State<SharedState>,
    Path(session_id): Path<Uuid>,
    headers: axum::http::HeaderMap,
) -> AppResult<impl IntoResponse> {
    let claims = extract_bearer_user(&state, &headers).await?;
    let caller_id = Uuid::parse_str(&claims.sub).map_err(|_| {
        crate::handlers::ApiError(authsvc_core::AuthError::InvalidToken)
    })?;
    let account_id = Uuid::parse_str(&claims.account_id).map_err(|_| {
        crate::handlers::ApiError(authsvc_core::AuthError::InvalidToken)
    })?;
    let owner_id = sessions::session_user_id(&state, session_id).await?;
    authorize_user_access(&state, caller_id, account_id, owner_id).await?;
    sessions::revoke_session(&state, session_id).await?;
    Ok(Json(json!({"revoked": true})))
}

pub async fn revoke_all_sessions(
    State(state): State<SharedState>,
    Path(user_id): Path<Uuid>,
    headers: axum::http::HeaderMap,
) -> AppResult<impl IntoResponse> {
    let claims = extract_bearer_user(&state, &headers).await?;
    let caller_id = Uuid::parse_str(&claims.sub).map_err(|_| {
        crate::handlers::ApiError(authsvc_core::AuthError::InvalidToken)
    })?;
    let account_id = Uuid::parse_str(&claims.account_id).map_err(|_| {
        crate::handlers::ApiError(authsvc_core::AuthError::InvalidToken)
    })?;
    authorize_user_access(&state, caller_id, account_id, user_id).await?;
    let count = sessions::revoke_all_sessions(&state, user_id).await?;
    Ok(Json(json!({"revoked": count})))
}
