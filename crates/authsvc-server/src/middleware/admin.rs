use axum::{
    extract::{Request, State},
    http::{header::AUTHORIZATION, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use serde_json::json;

use crate::{handlers::SharedState, services::auth::validate_bearer_token};

pub async fn require_admin(
    State(state): State<SharedState>,
    request: Request,
    next: Next,
) -> Response {
    let auth_header = request
        .headers()
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok());

    // Bootstrap secret for initial setup
    if let Some(secret) = &state.config.bootstrap_secret {
        if let Some(hdr) = auth_header {
            if hdr == format!("Bearer {secret}") {
                return next.run(request).await;
            }
        }
    }

    // Bearer access token with admin permission
    if let Some(hdr) = auth_header {
        if let Some(token) = hdr.strip_prefix("Bearer ") {
            if validate_bearer_token(state.as_ref(), token)
                .await
                .is_ok()
            {
                return next.run(request).await;
            }
        }
    }

    (
        StatusCode::UNAUTHORIZED,
        axum::Json(json!({
            "error": "unauthorized",
            "error_description": "admin token or bootstrap secret required"
        })),
    )
        .into_response()
}

pub async fn require_bootstrap_or_open(
    State(state): State<SharedState>,
    request: Request,
    next: Next,
) -> Response {
    let user_count = match state.store.count_users().await {
        Ok(n) => n,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                axum::Json(json!({"error": "server_error"})),
            )
                .into_response()
        }
    };

    if user_count == 0 {
        return next.run(request).await;
    }

    require_admin(State(state), request, next).await
}
