use axum::{
    extract::{Path, State},
    response::IntoResponse,
    Json,
};
use serde_json::json;
use uuid::Uuid;

use crate::{
    handlers::{auth::extract_bearer_user, AppResult, SharedState},
    services::sessions,
};

pub async fn list_sessions(
    State(state): State<SharedState>,
    Path(user_id): Path<Uuid>,
    headers: axum::http::HeaderMap,
) -> AppResult<impl IntoResponse> {
    let _claims = extract_bearer_user(&state, &headers).await?;
    let sessions = sessions::list_sessions(&state, user_id).await?;
    Ok(Json(json!({"sessions": sessions})))
}

pub async fn revoke_session(
    State(state): State<SharedState>,
    Path(session_id): Path<Uuid>,
    headers: axum::http::HeaderMap,
) -> AppResult<impl IntoResponse> {
    let _claims = extract_bearer_user(&state, &headers).await?;
    sessions::revoke_session(&state, session_id).await?;
    Ok(Json(json!({"revoked": true})))
}

pub async fn revoke_all_sessions(
    State(state): State<SharedState>,
    Path(user_id): Path<Uuid>,
    headers: axum::http::HeaderMap,
) -> AppResult<impl IntoResponse> {
    let _claims = extract_bearer_user(&state, &headers).await?;
    let count = sessions::revoke_all_sessions(&state, user_id).await?;
    Ok(Json(json!({"revoked": count})))
}
