use axum::{
    extract::{Path, State},
    http::header::AUTHORIZATION,
    response::IntoResponse,
    Json,
};

use crate::{
    handlers::{ApiError, AppResult, SharedState},
    services::compliance,
};
use uuid::Uuid;

pub async fn compliance_status(
    State(state): State<SharedState>,
    headers: axum::http::HeaderMap,
) -> AppResult<impl IntoResponse> {
    let account_id = extract_account_from_auth(&state, &headers).await?;
    let status = compliance::compliance_status(&state, account_id).await?;
    Ok(Json(status))
}

async fn extract_account_from_auth(
    state: &SharedState,
    headers: &axum::http::HeaderMap,
) -> Result<Uuid, ApiError> {
    if let Some(hdr) = headers.get(AUTHORIZATION).and_then(|v| v.to_str().ok()) {
        if let Some(token) = hdr.strip_prefix("Bearer ") {
            let claims = crate::services::auth::validate_bearer_token(state, token).await?;
            if let Ok(account_id) = Uuid::parse_str(&claims.account_id) {
                if account_id != Uuid::nil() {
                    return Ok(account_id);
                }
            }
        }
    }
    crate::services::admin::default_account_id(state)
        .await
        .map_err(ApiError)
}
