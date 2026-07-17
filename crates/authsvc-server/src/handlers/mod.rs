use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use authsvc_core::AuthError;
use serde_json::json;

pub mod auth;
pub mod authz;
pub mod oidc;

pub struct ApiError(AuthError);

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
            AuthError::UserAlreadyExists => (StatusCode::CONFLICT, "user_exists"),
            AuthError::UserNotFound | AuthError::ClientNotFound | AuthError::NotFound(_) => {
                (StatusCode::NOT_FOUND, "not_found")
            }
            AuthError::Validation(_) | AuthError::UnsupportedGrantType(_) => {
                (StatusCode::BAD_REQUEST, "invalid_request")
            }
            AuthError::AccountLocked(_) => (StatusCode::LOCKED, "account_locked"),
            AuthError::Internal(_) => (StatusCode::INTERNAL_SERVER_ERROR, "server_error"),
        };

        (
            status,
            Json(json!({
                "error": code,
                "error_description": self.0.to_string()
            })),
        )
            .into_response()
    }
}

pub async fn health() -> impl IntoResponse {
    Json(json!({ "status": "ok", "service": "authsvc" }))
}

pub type AppResult<T> = Result<T, ApiError>;

pub type SharedState = std::sync::Arc<crate::services::AppState>;
