use axum::{
    extract::{Path, State},
    http::{header::AUTHORIZATION, StatusCode},
    response::IntoResponse,
    Json,
};
use serde::Deserialize;
use serde_json::json;
use uuid::Uuid;

use crate::{
    handlers::{ApiError, AppResult, SharedState},
    services::scim::{self, authenticate_scim},
};

async fn scim_account(state: &SharedState, headers: &axum::http::HeaderMap) -> Result<Uuid, ApiError> {
    let hdr = headers
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or(ApiError(authsvc_core::AuthError::Forbidden))?;
    let token = hdr
        .strip_prefix("Bearer ")
        .ok_or(ApiError(authsvc_core::AuthError::Forbidden))?;
    let account_id = authenticate_scim(state, token).await?;
    scim_rate_limit(state, account_id).await?;
    Ok(account_id)
}

async fn scim_rate_limit(state: &SharedState, account_id: Uuid) -> Result<(), ApiError> {
    let limit = if let Some(override_limit) = state
        .repos
        .postgres()
        .account_rate_limit_override(account_id)
        .await?
    {
        if override_limit > 0 {
            override_limit as u32
        } else {
            state.config.rate_limit_per_minute
        }
    } else {
        state.config.rate_limit_per_minute
    };
    state
        .rate_limiter
        .check_with_limit(&format!("scim:{account_id}"), limit)
        .await?;
    Ok(())
}

pub async fn list_users(
    State(state): State<SharedState>,
    headers: axum::http::HeaderMap,
) -> AppResult<impl IntoResponse> {
    let account_id = scim_account(&state, &headers).await?;
    Ok(Json(scim::list_users(&state, account_id).await?))
}

pub async fn get_user(
    State(state): State<SharedState>,
    Path(id): Path<Uuid>,
    headers: axum::http::HeaderMap,
) -> AppResult<impl IntoResponse> {
    let account_id = scim_account(&state, &headers).await?;
    Ok(Json(scim::get_user(&state, account_id, id).await?))
}

#[derive(Debug, Deserialize)]
pub struct ScimCreateUser {
    pub userName: String,
    #[serde(default)]
    pub displayName: Option<String>,
}

pub async fn create_user(
    State(state): State<SharedState>,
    headers: axum::http::HeaderMap,
    Json(body): Json<ScimCreateUser>,
) -> AppResult<impl IntoResponse> {
    let account_id = scim_account(&state, &headers).await?;
    let user = scim::create_user(
        &state,
        account_id,
        &body.userName,
        body.displayName.as_deref(),
    )
    .await?;
    Ok((StatusCode::CREATED, Json(user)))
}

pub async fn delete_user(
    State(state): State<SharedState>,
    Path(id): Path<Uuid>,
    headers: axum::http::HeaderMap,
) -> AppResult<impl IntoResponse> {
    let account_id = scim_account(&state, &headers).await?;
    scim::delete_user(&state, account_id, id).await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn list_groups(
    State(state): State<SharedState>,
    headers: axum::http::HeaderMap,
) -> AppResult<impl IntoResponse> {
    let account_id = scim_account(&state, &headers).await?;
    Ok(Json(scim::list_groups(&state, account_id).await?))
}

pub async fn get_group(
    State(state): State<SharedState>,
    Path(id): Path<Uuid>,
    headers: axum::http::HeaderMap,
) -> AppResult<impl IntoResponse> {
    let account_id = scim_account(&state, &headers).await?;
    Ok(Json(scim::get_group(&state, account_id, id).await?))
}

pub async fn patch_user(
    State(state): State<SharedState>,
    Path(id): Path<Uuid>,
    headers: axum::http::HeaderMap,
    Json(body): Json<scim::ScimPatchRequest>,
) -> AppResult<impl IntoResponse> {
    let account_id = scim_account(&state, &headers).await?;
    Ok(Json(scim::patch_user(&state, account_id, id, body).await?))
}

pub async fn patch_group(
    State(state): State<SharedState>,
    Path(id): Path<Uuid>,
    headers: axum::http::HeaderMap,
    Json(body): Json<scim::ScimPatchRequest>,
) -> AppResult<impl IntoResponse> {
    let account_id = scim_account(&state, &headers).await?;
    Ok(Json(scim::patch_group(&state, account_id, id, body).await?))
}
