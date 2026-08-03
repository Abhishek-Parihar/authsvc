use authsvc_core::{AuthError, SessionStore};
use serde_json::{json, Value};
use uuid::Uuid;

use super::state::AppState;

pub async fn list_sessions(state: &AppState, user_id: Uuid) -> Result<Vec<Value>, AuthError> {
    let session_ids = SessionStore::list_for_user(&state.sessions, user_id).await?;
    let sessions = session_ids
        .into_iter()
        .map(|session_id| json!({"session_id": session_id, "user_id": user_id}))
        .collect();
    Ok(sessions)
}

pub async fn session_user_id(state: &AppState, session_id: Uuid) -> Result<Uuid, AuthError> {
    SessionStore::get_user_id(&state.sessions, session_id)
        .await?
        .ok_or(AuthError::NotFound("session".into()))
}

pub async fn revoke_session(state: &AppState, session_id: Uuid) -> Result<(), AuthError> {
    state.sessions.delete(session_id).await
}

pub async fn revoke_all_sessions(state: &AppState, user_id: Uuid) -> Result<u64, AuthError> {
    state.sessions.revoke_all_for_user(user_id).await
}
