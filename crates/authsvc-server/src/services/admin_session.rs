use authsvc_core::AuthError;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::state::AppState;
use crate::services::{admin::default_account_id, authz::user_has_admin_permission};

const ADMIN_SESSION_TTL_SECS: u64 = 8 * 3600;
const ADMIN_SESSION_COOKIE: &str = "authsvc_admin_session";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum AdminSessionKind {
    Bootstrap,
    User { user_id: Uuid },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AdminSessionData {
    kind: AdminSessionKind,
    account_id: Uuid,
}

pub fn admin_session_cookie_name() -> &'static str {
    ADMIN_SESSION_COOKIE
}

pub async fn create_admin_session(
    state: &AppState,
    token: &str,
    cookie_secure: bool,
) -> Result<(String, String), AuthError> {
    let session_data = resolve_session_data(state, token).await?;

    let session_id = Uuid::new_v4();
    state
        .sessions
        .set_json(
            &format!("admin_session:{session_id}"),
            &session_data,
            ADMIN_SESSION_TTL_SECS,
        )
        .await?;

    let cookie = format!(
        "{ADMIN_SESSION_COOKIE}={session_id}; HttpOnly; Path=/; SameSite=Strict; Max-Age={ADMIN_SESSION_TTL_SECS}{}",
        if cookie_secure { "; Secure" } else { "" }
    );
    Ok((session_id.to_string(), cookie))
}

pub async fn delete_admin_session(state: &AppState, session_id: &str) -> Result<(), AuthError> {
    state
        .sessions
        .delete_key(&format!("admin_session:{session_id}"))
        .await
}

pub async fn validate_admin_session(state: &AppState, session_id: &str) -> Result<(), AuthError> {
    let data: Option<AdminSessionData> = state
        .sessions
        .get_json(&format!("admin_session:{session_id}"))
        .await?;

    let data = data.ok_or(AuthError::InvalidToken)?;

    match data.kind {
        AdminSessionKind::Bootstrap => {
            if state.config.is_production()
                && (!state.config.allow_bootstrap_secret || state.config.bootstrap_secret.is_none())
            {
                return Err(AuthError::Forbidden);
            }
            Ok(())
        },
        AdminSessionKind::User { user_id } => {
            if user_has_admin_permission(state, user_id, data.account_id).await? {
                Ok(())
            } else {
                Err(AuthError::Forbidden)
            }
        }
    }
}

pub async fn is_admin_session_valid(state: &AppState, session_id: &str) -> Result<bool, AuthError> {
    match validate_admin_session(state, session_id).await {
        Ok(()) => Ok(true),
        Err(AuthError::InvalidToken) => Ok(false),
        Err(e) => Err(e),
    }
}

async fn resolve_session_data(state: &AppState, token: &str) -> Result<AdminSessionData, AuthError> {
    if crate::middleware::bootstrap_token_matches(&state.config, token) {
        let account_id = default_account_id(state).await?;
        return Ok(AdminSessionData {
            kind: AdminSessionKind::Bootstrap,
            account_id,
        });
    }

    let claims = state.jwt.validate_access_token(token)?;
    let user_id = Uuid::parse_str(&claims.sub).map_err(|_| AuthError::Forbidden)?;
    let account_id = match Uuid::parse_str(&claims.account_id) {
        Ok(id) if id != Uuid::nil() => id,
        _ => default_account_id(state).await?,
    };
    if user_has_admin_permission(state, user_id, account_id).await? {
        Ok(AdminSessionData {
            kind: AdminSessionKind::User { user_id },
            account_id,
        })
    } else {
        Err(AuthError::Forbidden)
    }
}
