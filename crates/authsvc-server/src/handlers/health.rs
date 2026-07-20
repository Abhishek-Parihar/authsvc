use axum::{extract::State, Json};
use serde_json::json;

use crate::handlers::{AppResult, SharedState};

pub async fn health() -> impl axum::response::IntoResponse {
    Json(json!({ "status": "ok", "service": "authsvc" }))
}

pub async fn ready(State(state): State<SharedState>) -> AppResult<impl axum::response::IntoResponse> {
    state.repos.health().ping().await?;
    let mut conn = state
        .sessions
        .pool()
        .get()
        .await
        .map_err(|e| authsvc_core::AuthError::Internal(e.to_string()))?;
    let _: String = deadpool_redis::redis::AsyncCommands::ping(&mut conn)
        .await
        .map_err(|e| authsvc_core::AuthError::Internal(e.to_string()))?;
    Ok(Json(json!({ "status": "ready" })))
}

pub async fn metrics(
    handle: metrics_exporter_prometheus::PrometheusHandle,
) -> impl axum::response::IntoResponse {
    (
        [(axum::http::header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        handle.render(),
    )
}
