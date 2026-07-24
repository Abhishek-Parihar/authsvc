use axum::{
    body::Body,
    extract::State,
    http::{header::AUTHORIZATION, Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use serde_json::json;

use crate::handlers::SharedState;

pub async fn require_metrics_token(
    State(state): State<SharedState>,
    req: Request<Body>,
    next: Next,
) -> Response {
    let Some(expected) = &state.config.metrics_bearer_token else {
        return next.run(req).await;
    };

    let authorized = req
        .headers()
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|hdr| hdr == format!("Bearer {expected}"));

    if authorized {
        next.run(req).await
    } else {
        (
            StatusCode::UNAUTHORIZED,
            axum::Json(json!({
                "error": "unauthorized",
                "error_description": "metrics bearer token required"
            })),
        )
            .into_response()
    }
}
