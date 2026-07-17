use axum::extract::{Request, State};
use axum::http::{header::AUTHORIZATION, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use serde_json::json;

use crate::JwksValidator;

/// Axum middleware that validates `Authorization: Bearer <token>` via JWKS.
pub async fn require_bearer(
    State(validator): State<JwksValidator>,
    mut req: Request,
    next: Next,
) -> Response {
    let auth = req
        .headers()
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok());

    let Some(hdr) = auth else {
        return unauthorized();
    };
    let Some(token) = hdr.strip_prefix("Bearer ") else {
        return unauthorized();
    };

    match validator.validate(token).await {
        Ok(claims) => {
            req.extensions_mut().insert(claims);
            next.run(req).await
        }
        Err(_) => unauthorized(),
    }
}

fn unauthorized() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        axum::Json(json!({"error": "unauthorized"})),
    )
        .into_response()
}
