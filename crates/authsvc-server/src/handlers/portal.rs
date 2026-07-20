use axum::{
    extract::{Query, State},
    response::IntoResponse,
    Json,
};
use std::collections::HashMap;

use crate::{
    handlers::{ApiError, AppResult, SharedState},
    services::portal::resolve_portal_by_domain,
};
use authsvc_core::AuthError;

pub async fn get_portal_from_map(
    State(state): State<SharedState>,
    Query(params): Query<HashMap<String, String>>,
) -> AppResult<impl IntoResponse> {
    let domain = params
        .get("domain")
        .ok_or_else(|| ApiError(AuthError::Validation("domain required".into())))?;
    let portal = resolve_portal_by_domain(&state, domain).await?;
    Ok(Json(portal))
}
