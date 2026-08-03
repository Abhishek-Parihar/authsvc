use axum::{
    body::Body,
    extract::State,
    http::Request,
    middleware::Next,
    response::Response,
};

use crate::handlers::{ApiError, SharedState};

pub async fn ip_rate_limit(
    State(state): State<SharedState>,
    request: Request<Body>,
    next: Next,
) -> Result<Response, ApiError> {
    let ip = client_ip(request.headers());
    state
        .rate_limiter
        .check_with_limit(&format!("ip:{ip}"), state.config.ip_rate_limit_per_minute)
        .await?;
    Ok(next.run(request).await)
}

fn client_ip(headers: &axum::http::HeaderMap) -> String {
    if let Some(forwarded) = headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
    {
        if let Some(first) = forwarded.split(',').next() {
            let ip = first.trim();
            if !ip.is_empty() {
                return ip.to_string();
            }
        }
    }
    if let Some(real) = headers
        .get("x-real-ip")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        return real.to_string();
    }
    "unknown".to_string()
}
