use axum::{
    extract::{Path, State},
    response::IntoResponse,
    Json,
};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::{
    handlers::{AppResult, SharedState},
    services::{admin::default_account_id, idp_config},
};

#[derive(Debug, Deserialize)]
pub struct IdpConfigBody {
    pub enabled: bool,
    pub config: Value,
}

pub async fn list_idp_configs(
    State(state): State<SharedState>,
) -> AppResult<impl IntoResponse> {
    let account_id = default_account_id(&state).await?;
    let configs = idp_config::list_idp_configs(&state, account_id).await?;
    Ok(Json(json!({"configs": configs})))
}

pub async fn upsert_idp_config(
    State(state): State<SharedState>,
    Path(provider): Path<String>,
    Json(body): Json<IdpConfigBody>,
) -> AppResult<impl IntoResponse> {
    let account_id = default_account_id(&state).await?;
    let id = idp_config::upsert_idp_config(
        &state,
        account_id,
        &provider,
        body.enabled,
        body.config,
    )
    .await?;
    Ok(Json(json!({"id": id})))
}

pub async fn delete_idp_config(
    State(state): State<SharedState>,
    Path(provider): Path<String>,
) -> AppResult<impl IntoResponse> {
    let account_id = default_account_id(&state).await?;
    idp_config::delete_idp_config(&state, account_id, &provider).await?;
    Ok(Json(json!({"deleted": true})))
}
