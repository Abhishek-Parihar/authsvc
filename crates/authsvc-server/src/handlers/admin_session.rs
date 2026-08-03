use axum::{
    extract::State,
    http::{header::SET_COOKIE, HeaderMap, HeaderValue, StatusCode},
    response::IntoResponse,
    Json,
};
use serde::Deserialize;
use serde_json::json;

use crate::{
    handlers::{ApiError, AppResult, SharedState},
    services::admin_session,
};

#[derive(Debug, Deserialize)]
pub struct AdminSessionRequest {
    pub token: String,
}

pub async fn create_session(
    State(state): State<SharedState>,
    Json(body): Json<AdminSessionRequest>,
) -> AppResult<impl IntoResponse> {
    let (_, cookie) = admin_session::create_admin_session(
        &state,
        &body.token,
        state.config.cookie_secure,
    )
    .await
    .map_err(ApiError)?;

    Ok((
        StatusCode::NO_CONTENT,
        [(SET_COOKIE, HeaderValue::from_str(&cookie).map_err(|e| ApiError(authsvc_core::AuthError::Internal(e.to_string())))?)],
    ))
}

pub async fn delete_session(
    State(state): State<SharedState>,
    headers: HeaderMap,
) -> AppResult<impl IntoResponse> {
    if let Some(id) = admin_session_id_from_headers(&headers) {
        admin_session::delete_admin_session(&state, &id).await?;
    }
    let clear = format!(
        "{}=; HttpOnly; Path=/; Max-Age=0",
        admin_session::admin_session_cookie_name()
    );
    Ok((
        StatusCode::NO_CONTENT,
        [(SET_COOKIE, HeaderValue::from_str(&clear).map_err(|e| ApiError(authsvc_core::AuthError::Internal(e.to_string())))?)],
    ))
}

pub async fn session_status(
    State(state): State<SharedState>,
    headers: HeaderMap,
) -> AppResult<impl IntoResponse> {
    let connected = if let Some(id) = admin_session_id_from_headers(&headers) {
        admin_session::is_admin_session_valid(&state, &id).await?
    } else {
        false
    };
    Ok(Json(json!({"connected": connected})))
}

pub fn admin_session_id_from_headers(headers: &HeaderMap) -> Option<String> {
    let cookie = headers.get(axum::http::header::COOKIE)?.to_str().ok()?;
    let name = admin_session::admin_session_cookie_name();
    cookie.split(';').find_map(|part| {
        let part = part.trim();
        part.strip_prefix(&format!("{name}="))
            .map(str::to_string)
    })
}
