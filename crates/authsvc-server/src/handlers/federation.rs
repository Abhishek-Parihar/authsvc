use axum::{
    extract::{Path, Query, State},
    response::Redirect,
};
use serde::Deserialize;
use std::collections::HashMap;

use crate::{
    handlers::{ApiError, AppResult, SharedState},
    services::federation::{federation_callback, start_federation},
};
use authsvc_core::AuthError;
use uuid::Uuid;

pub async fn federate_start(
    State(state): State<SharedState>,
    Path(provider): Path<String>,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> AppResult<Redirect> {
    let account_id = params
        .get("account_id")
        .and_then(|s| Uuid::parse_str(s).ok());
    let url = start_federation(&state, &provider, account_id).await?;
    Ok(Redirect::temporary(&url))
}

#[derive(Debug, Deserialize)]
pub struct FederateCallbackQuery {
    pub code: String,
    pub state: String,
    pub client_id: String,
}

pub async fn federate_callback(
    State(state): State<SharedState>,
    Path(provider): Path<String>,
    Query(q): Query<FederateCallbackQuery>,
) -> AppResult<impl axum::response::IntoResponse> {
    let _ = provider;
    let tokens = federation_callback(&state, &q.state, &q.code, &q.client_id, None).await?;
    Ok(axum::Json(tokens))
}

pub async fn federate_callback_post(
    State(state): State<SharedState>,
    Path(provider): Path<String>,
    axum::Json(body): axum::Json<HashMap<String, String>>,
) -> AppResult<impl axum::response::IntoResponse> {
    let _ = provider;
    let code = body
        .get("code")
        .ok_or_else(|| ApiError(AuthError::Validation("code required".into())))?;
    let state_param = body
        .get("state")
        .ok_or_else(|| ApiError(AuthError::Validation("state required".into())))?;
    let client_id = body
        .get("client_id")
        .ok_or_else(|| ApiError(AuthError::Validation("client_id required".into())))?;
    let tokens = federation_callback(&state, state_param, code, client_id, None).await?;
    Ok(axum::Json(tokens))
}
