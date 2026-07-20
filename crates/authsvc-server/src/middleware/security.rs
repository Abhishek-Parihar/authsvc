use axum::{
    body::Body,
    http::{HeaderValue, Request, Response},
    middleware::Next,
};

use crate::handlers::SharedState;

pub async fn security_headers(
    State(state): State<SharedState>,
    req: Request<Body>,
    next: Next,
) -> Response<Body> {
    let mut resp = next.run(req).await;
    let headers = resp.headers_mut();
    headers.insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    headers.insert("x-frame-options", HeaderValue::from_static("DENY"));
    headers.insert(
        "referrer-policy",
        HeaderValue::from_static("strict-origin-when-cross-origin"),
    );
    if state.config.is_production() {
        headers.insert(
            "strict-transport-security",
            HeaderValue::from_static("max-age=31536000; includeSubDomains"),
        );
        headers.insert(
            "content-security-policy",
            HeaderValue::from_static("default-src 'none'; frame-ancestors 'none'"),
        );
    }
    resp
}

use axum::extract::State;
use uuid::Uuid;

pub async fn set_account_context(
    State(state): State<SharedState>,
    req: Request<Body>,
    next: Next,
) -> Response<Body> {
    if let Some(hdr) = req
        .headers()
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
    {
        if let Some(token) = hdr.strip_prefix("Bearer ") {
            if let Ok(claims) = crate::services::auth::validate_bearer_token(&state, token).await {
                if let Ok(account_id) = Uuid::parse_str(&claims.account_id) {
                    let _ = state
                        .repos
                        .postgres()
                        .set_account_context(account_id)
                        .await;
                }
            }
        }
    }
    next.run(req).await
}
