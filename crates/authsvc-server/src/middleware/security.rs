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
    mut req: Request<Body>,
    next: Next,
) -> Response<Body> {
    let mut account_id: Option<Uuid> = None;

    if let Some(hdr) = req
        .headers()
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
    {
        if let Some(token) = hdr.strip_prefix("Bearer ") {
            if state
                .config
                .bootstrap_secret
                .as_deref()
                .is_some_and(|secret| token == secret)
            {
                account_id = crate::services::admin::default_account_id(&state).await.ok();
            } else if let Ok(claims) =
                crate::services::auth::validate_bearer_token(&state, token).await
            {
                account_id = Uuid::parse_str(&claims.account_id).ok().filter(|id| *id != Uuid::nil());
            }
        }
    }

    if let Some(aid) = account_id {
        let _ = state.repos.postgres().set_account_context(aid).await;
        req.extensions_mut().insert(aid);
    }

    next.run(req).await
}
