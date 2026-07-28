use axum::{
    extract::{Request, State},
    http::{header::AUTHORIZATION, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use serde_json::json;
use uuid::Uuid;

use crate::{
    handlers::{admin_session::admin_session_id_from_headers, SharedState},
    middleware::{api_key_has_admin, authenticate, extract_api_key, AuthContext},
    services::{
        admin_session::resolve_admin_bearer_from_cookie,
        api_keys::validate_api_key,
        auth::is_bootstrap_open,
        authz::user_has_admin_permission,
    },
};

pub async fn require_admin(
    State(state): State<SharedState>,
    mut request: Request,
    next: Next,
) -> Response {
    if let Some(session_id) = admin_session_id_from_headers(request.headers()) {
        if let Ok(Some(token)) = resolve_admin_bearer_from_cookie(&state, &session_id).await {
            if request.headers().get(AUTHORIZATION).is_none() {
                request.headers_mut().insert(
                    AUTHORIZATION,
                    format!("Bearer {token}")
                        .parse()
                        .expect("valid bearer header"),
                );
            }
        }
    }

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
        Ok(AuthContext::UserJwt(claims)) => {
            let user_id = match Uuid::parse_str(&claims.sub) {
                Ok(id) => id,
                Err(_) => return forbidden(),
            };
            let account_id = match Uuid::parse_str(&claims.account_id) {
                Ok(id) if id != Uuid::nil() => id,
                _ => return forbidden(),
            };
            match user_has_admin_permission(state.as_ref(), user_id, account_id).await {
                Ok(true) => next.run(request).await,
                Ok(false) => forbidden(),
                Err(_) => unauthorized(),
            }
        }
        Ok(AuthContext::ApiKey { .. }) => forbidden(),
        Err(_) => unauthorized(),
    }
}

pub async fn require_authenticated(
    State(state): State<SharedState>,
    request: Request,
    next: Next,
) -> Response {
    if let Some(secret) = &state.config.bootstrap_secret {
        if let Some(hdr) = request
            .headers()
            .get(AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
        {
            if hdr == format!("Bearer {secret}") {
                return next.run(request).await;
            }
        }
    }

    if extract_api_key(request.headers()).is_some() {
        return next.run(request).await;
    }

    match authenticate(&state, request.headers()).await {
        Ok(AuthContext::UserJwt(_)) => next.run(request).await,
        Ok(AuthContext::ApiKey { .. }) => next.run(request).await,
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

fn forbidden() -> Response {
    (
        StatusCode::FORBIDDEN,
        axum::Json(json!({
            "error": "forbidden",
            "error_description": "account admin permission required"
        })),
    )
        .into_response()
}
