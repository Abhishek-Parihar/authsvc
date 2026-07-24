use thiserror::Error;

#[derive(Debug, Error)]
pub enum AuthError {
    #[error("invalid credentials")]
    InvalidCredentials,
    #[error("user not found")]
    UserNotFound,
    #[error("user already exists")]
    UserAlreadyExists,
    #[error("client not found")]
    ClientNotFound,
    #[error("invalid client credentials")]
    InvalidClientCredentials,
    #[error("unsupported grant type: {0}")]
    UnsupportedGrantType(String),
    #[error("invalid or expired token")]
    InvalidToken,
    #[error("token reuse detected")]
    TokenReuse,
    #[error("account locked until {0}")]
    AccountLocked(String),
    #[error("forbidden")]
    Forbidden,
    #[error("validation error: {0}")]
    Validation(String),
    #[error("authorization pending")]
    AuthorizationPending,
    #[error("slow down")]
    SlowDown,
    #[error("not found: {0}")]
    NotFound(String),
    #[error("internal error: {0}")]
    Internal(String),
}
