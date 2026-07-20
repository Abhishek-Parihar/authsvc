use axum::{
    extract::{Request, State},
    http::{header::AUTHORIZATION, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use serde_json::json;

use crate::{
    handlers::SharedState,
    middleware::{api_key_has_admin, authenticate, extract_api_key, AuthContext},
    services::{api_keys::validate_api_key, auth::is_bootstrap_open},
};

pub async fn require_admin(
    State(state): State<SharedState>,
    request: Request,
    next: Next,
) -> Response {
    let auth_header = request
        .headers()
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok());

    if let Some(secret) = &state.config.bootstrap_secret {
        if let Some(hdr) = auth_header {
            if hdr == format!("Bearer {secret}") {
                return next.run(request).await;
            }
        }
    }

    if let Some(key) = extract_api_key(request.headers()) {
        if let Ok((_, _, scopes)) = validate_api_key(state.as_ref(), &key).await {
            if api_key_has_admin(&scopes) {
                return next.run(request).await;
            }
        }
    }

    match authenticate(&state, request.headers()).await {
        Ok(AuthContext::UserJwt(_)) => next.run(request).await,
        Ok(AuthContext::ApiKey { .. }) => unauthorized(),
        Err(_) => unauthorized(),
    }
}

pub async fn require_bootstrap_or_open(
    State(state): State<SharedState>,
    request: Request,
    next: Next,
) -> Response {
    let user_count = match is_bootstrap_open(state.as_ref()).await {
        Ok(true) => 0,
        Ok(false) => 1,
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

fn unauthorized() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        axum::Json(json!({
            "error": "unauthorized",
            "error_description": "admin token, bootstrap secret, or API key with admin scope required"
        })),
    )
        .into_response()
}
