use axum::{
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use authsvc_core::AuthError;
use serde_json::json;

pub mod admin;
pub mod admin_session;
pub mod auth;
pub mod compliance;
pub mod device;
pub mod federation;
pub mod health;
pub mod idp_config;
pub mod oidc;
pub mod portal;
pub mod privacy;
pub mod saml;
pub mod saml_idp;
pub mod scim;
pub mod sessions;
pub mod ui;
pub mod webauthn;

pub struct ApiError(pub AuthError);

impl From<AuthError> for ApiError {
    fn from(value: AuthError) -> Self {
        Self(value)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, code) = match &self.0 {
            AuthError::InvalidCredentials | AuthError::InvalidClientCredentials => {
                (StatusCode::UNAUTHORIZED, "invalid_credentials")
            }
            AuthError::InvalidToken | AuthError::TokenReuse => {
                (StatusCode::UNAUTHORIZED, "invalid_token")
            }
            AuthError::Forbidden => (StatusCode::FORBIDDEN, "forbidden"),
            AuthError::RateLimited(secs) => {
                let retry_after = header::HeaderValue::from_str(&secs.to_string())
                    .unwrap_or_else(|_| header::HeaderValue::from_static("60"));
                return (
                    StatusCode::TOO_MANY_REQUESTS,
                    [(header::RETRY_AFTER, retry_after)],
                    Json(json!({
                        "error": "rate_limited",
                        "error_description": format!("retry after {secs} seconds")
                    })),
                )
                    .into_response();
            }
            AuthError::UserAlreadyExists => (StatusCode::CONFLICT, "user_exists"),
            AuthError::UserNotFound | AuthError::ClientNotFound | AuthError::NotFound(_) => {
                (StatusCode::NOT_FOUND, "not_found")
            }
            AuthError::Validation(_) | AuthError::UnsupportedGrantType(_) => {
                (StatusCode::BAD_REQUEST, "invalid_request")
            }
            AuthError::AuthorizationPending => (StatusCode::BAD_REQUEST, "authorization_pending"),
            AuthError::SlowDown => (StatusCode::BAD_REQUEST, "slow_down"),
            AuthError::AccountLocked(_) => (StatusCode::LOCKED, "account_locked"),
            AuthError::Internal(_) => (StatusCode::INTERNAL_SERVER_ERROR, "server_error"),
        };

        (
            status,
            Json(json!({
                "error": code,
                "error_description": error_description(&self.0)
            })),
        )
            .into_response()
    }
}

fn error_description(err: &AuthError) -> String {
    match err {
        AuthError::Internal(_) => "internal server error".into(),
        AuthError::AuthorizationPending => "authorization pending".into(),
        AuthError::SlowDown => "slow down".into(),
        AuthError::RateLimited(secs) => format!("retry after {secs} seconds"),
        other => other.to_string(),
    }
}

pub type AppResult<T> = Result<T, ApiError>;

pub type SharedState = std::sync::Arc<crate::services::AppState>;
