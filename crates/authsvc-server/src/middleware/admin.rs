use axum::{
    extract::State,
    middleware::Next,
    response::Response,
};

use crate::{
    handlers::{admin_session::admin_session_id_from_headers, SharedState},
    services::admin_session::validate_admin_session,
};

pub async fn require_admin(
    State(state): State<SharedState>,
    request: axum::http::Request<axum::body::Body>,
    next: Next,
) -> Response {
    if let Some(session_id) = admin_session_id_from_headers(request.headers()) {
        if validate_admin_session(&state, &session_id).await.is_ok() {
            return next.run(request).await;
        }
    }

    if crate::middleware::bootstrap_authorized(&state, request.headers()) {
        return next.run(request).await;
    }

    if let Some(key) = crate::middleware::extract_api_key(request.headers()) {
        if let Ok((_, _, scopes)) =
            crate::services::api_keys::validate_api_key(state.as_ref(), &key).await
        {
            if crate::middleware::api_key_has_admin(&scopes) {
                return next.run(request).await;
            }
        }
    }

    match crate::middleware::authenticate(&state, request.headers()).await {
        Ok(crate::middleware::AuthContext::UserJwt(claims)) => {
            let user_id = match uuid::Uuid::parse_str(&claims.sub) {
                Ok(id) => id,
                Err(_) => return forbidden(),
            };
            let account_id = match uuid::Uuid::parse_str(&claims.account_id) {
                Ok(id) if id != uuid::Uuid::nil() => id,
                _ => return forbidden(),
            };
            match crate::services::authz::user_has_admin_permission(
                state.as_ref(),
                user_id,
                account_id,
            )
            .await
            {
                Ok(true) => next.run(request).await,
                Ok(false) => forbidden(),
                Err(_) => unauthorized(),
            }
        }
        Ok(crate::middleware::AuthContext::ApiKey { .. }) => forbidden(),
        Err(_) => unauthorized(),
    }
}

pub async fn require_authenticated(
    State(state): State<SharedState>,
    request: axum::http::Request<axum::body::Body>,
    next: Next,
) -> Response {
    match crate::middleware::authenticate(&state, request.headers()).await {
        Ok(crate::middleware::AuthContext::UserJwt(_)) => next.run(request).await,
        Ok(crate::middleware::AuthContext::ApiKey { .. }) => forbidden(),
        Err(_) => unauthorized(),
    }
}

pub async fn require_bootstrap_or_open(
    State(state): State<SharedState>,
    request: axum::http::Request<axum::body::Body>,
    next: Next,
) -> Response {
    let user_count = match crate::services::auth::is_bootstrap_open(state.as_ref()).await {
        Ok(true) => 0,
        Ok(false) => 1,
        Err(_) => {
            return (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                axum::Json(serde_json::json!({"error": "server_error"})),
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
        axum::http::StatusCode::UNAUTHORIZED,
        axum::Json(serde_json::json!({
            "error": "unauthorized",
            "error_description": "admin token, bootstrap secret, or API key with admin scope required"
        })),
    )
        .into_response()
}

fn forbidden() -> Response {
    (
        axum::http::StatusCode::FORBIDDEN,
        axum::Json(serde_json::json!({
            "error": "forbidden",
            "error_description": "account admin permission required"
        })),
    )
        .into_response()
}

use axum::response::IntoResponse;
