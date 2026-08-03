use axum::{
    extract::{Query, State},
    response::{Html, IntoResponse},
    Form, Json,
};
use serde::Deserialize;

use crate::{
    handlers::{AppResult, SharedState},
    services::device_flow::{
        approve_device_code, create_device_csrf, start_device_authorization,
    },
};

#[derive(Debug, Deserialize)]
pub struct DeviceAuthRequest {
    pub client_id: String,
    pub client_secret: String,
    pub scope: Option<String>,
}

pub async fn device_authorization(
    State(state): State<SharedState>,
    Json(body): Json<DeviceAuthRequest>,
) -> AppResult<impl IntoResponse> {
    let resp = start_device_authorization(
        &state,
        &body.client_id,
        &body.client_secret,
        body.scope.as_deref(),
    )
    .await?;
    Ok(Json(resp))
}

#[derive(Debug, Deserialize)]
pub struct DevicePageQuery {
    pub user_code: Option<String>,
}

pub async fn device_page(
    State(state): State<SharedState>,
    Query(query): Query<DevicePageQuery>,
) -> AppResult<Html<String>> {
    let prefill = query.user_code.unwrap_or_default();
    let csrf = create_device_csrf(&state).await?;
    Ok(Html(
        crate::handlers::ui::device_html(&state.config.issuer, &prefill, &csrf),
    ))
}

#[derive(Debug, Deserialize)]
pub struct DeviceApproveForm {
    pub user_code: String,
    pub email: String,
    pub password: String,
    pub csrf_token: String,
}

pub async fn device_approve(
    State(state): State<SharedState>,
    Form(body): Form<DeviceApproveForm>,
) -> AppResult<impl IntoResponse> {
    approve_device_code(
        &state,
        &body.user_code.to_uppercase(),
        &body.email,
        &body.password,
        &body.csrf_token,
        None,
    )
    .await?;
    Ok(Html(crate::handlers::ui::device_success_html()))
}
