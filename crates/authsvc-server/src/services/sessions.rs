use authsvc_core::{AuthError, SessionStore};
use deadpool_redis::redis::AsyncCommands;
use serde_json::{json, Value};
use uuid::Uuid;

use super::state::AppState;

pub async fn list_sessions(state: &AppState, user_id: Uuid) -> Result<Vec<Value>, AuthError> {
    let mut conn = state
        .sessions
        .pool()
        .get()
        .await
        .map_err(|e| AuthError::Internal(e.to_string()))?;
    let pattern = format!("session:*");
    let keys: Vec<String> = conn
        .keys(pattern)
        .await
        .map_err(|e| AuthError::Internal(e.to_string()))?;

    let mut sessions = Vec::new();
    for key in keys {
        let val: Option<String> = conn
            .get(&key)
            .await
            .map_err(|e| AuthError::Internal(e.to_string()))?;
        if val.as_deref() == Some(&user_id.to_string()) {
            let session_id = key.strip_prefix("session:").unwrap_or(&key);
            sessions.push(json!({"session_id": session_id, "user_id": user_id}));
        }
    }
    Ok(sessions)
}

pub async fn revoke_session(state: &AppState, session_id: Uuid) -> Result<(), AuthError> {
    state.sessions.delete(session_id).await
}

pub async fn revoke_all_sessions(state: &AppState, user_id: Uuid) -> Result<u64, AuthError> {
    let sessions = list_sessions(state, user_id).await?;
    let mut count = 0u64;
    for s in sessions {
        if let Some(id) = s["session_id"].as_str() {
            if let Ok(uuid) = Uuid::parse_str(id) {
                state.sessions.delete(uuid).await?;
                count += 1;
            }
        }
    }
    Ok(count)
}
