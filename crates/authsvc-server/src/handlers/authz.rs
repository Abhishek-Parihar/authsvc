use axum::{extract::State, Json};
use authsvc_core::{AuthzCheck, AuthzResult};
use serde::Deserialize;
use uuid::Uuid;

use crate::{
    handlers::{AppResult, SharedState},
    services::authz::{check_authorization, parse_subject},
};

#[derive(Debug, Deserialize)]
pub struct AuthzCheckRequest {
    pub subject_id: String,
    pub tenant_id: String,
    pub action: String,
    pub resource: String,
    pub context: Option<serde_json::Value>,
}

pub async fn check(
    State(state): State<SharedState>,
    Json(body): Json<AuthzCheckRequest>,
) -> AppResult<Json<AuthzResult>> {
    let req = AuthzCheck {
        subject_id: parse_subject(&body.subject_id)?,
        tenant_id: Uuid::parse_str(&body.tenant_id)
            .map_err(|_| authsvc_core::AuthError::Validation("invalid tenant_id".into()))?,
        action: body.action,
        resource: body.resource,
        context: body.context,
    };
    let result = check_authorization(&state, req).await?;
    Ok(Json(result))
}
