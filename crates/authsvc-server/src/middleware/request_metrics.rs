use std::time::Instant;

use axum::{
    body::Body,
    http::Request,
    middleware::Next,
    response::Response,
};

pub async fn request_metrics(request: Request<Body>, next: Next) -> Response {
    let method = request.method().clone();
    let path = normalize_path(request.uri().path());
    let start = Instant::now();
    let response = next.run(request).await;
    let status = response.status();
    let elapsed = start.elapsed().as_secs_f64();

    crate::observability::record_http_request(
        method.as_str(),
        &path,
        status.as_u16(),
        elapsed,
    );

    response
}

fn normalize_path(path: &str) -> String {
    if path.starts_with("/scim/v2/Users/")
        || path.starts_with("/v1/users/")
        || path.starts_with("/v1/sessions/")
        || path.starts_with("/v1/clients/")
        || path.starts_with("/v1/accounts/")
        || path.starts_with("/v1/api-keys/")
        || path.starts_with("/v1/casbin/rules/")
        || path.starts_with("/v1/saml/service-providers/")
        || path.starts_with("/v1/idp-configs/")
    {
        let parts: Vec<&str> = path.split('/').collect();
        if parts.len() >= 3 {
            return format!("/{}/{}", parts[1], parts[2]);
        }
    }
    path.to_string()
}
