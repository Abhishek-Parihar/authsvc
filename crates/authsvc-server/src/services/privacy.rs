use authsvc_core::AuthError;
use serde_json::{json, Value};
use uuid::Uuid;

use super::state::AppState;

pub async fn export_user_data(
    state: &AppState,
    user_id: Uuid,
    account_id: Uuid,
) -> Result<Value, AuthError> {
    let user = state
        .repos
        .users()
        .find_by_id(user_id)
        .await?
        .ok_or(AuthError::UserNotFound)?;

    let memberships = state
        .repos
        .memberships()
        .list_user_accounts(user_id)
        .await?;
    let identities = state.repos.privacy().list_user_identities(user_id).await?;
    let audit = state
        .repos
        .privacy()
        .list_user_audit_events(user_id, 500)
        .await?;

    Ok(json!({
        "user": {
            "id": user.id,
            "email": user.email,
            "display_name": user.display_name,
            "email_verified": user.email_verified,
            "mfa_enabled": user.mfa_enabled,
            "status": user.status,
            "created_at": user.created_at,
        },
        "account_id": account_id,
        "memberships": memberships,
        "identities": identities,
        "audit_events": audit,
    }))
}

pub async fn request_export(
    state: &AppState,
    user_id: Uuid,
    account_id: Uuid,
) -> Result<(Uuid, Value), AuthError> {
    let export_id = state
        .repos
        .privacy()
        .create_export_request(user_id, account_id)
        .await?;
    let artifact = export_user_data(state, user_id, account_id).await?;
    state
        .repos
        .privacy()
        .complete_export_request(export_id, &artifact)
        .await?;
    state
        .audit(
            Some(account_id),
            Some(&user_id.to_string()),
            "privacy.export",
            Some("users"),
            None,
            json!({"export_id": export_id}),
        )
        .await?;
    Ok((export_id, artifact))
}

pub async fn delete_user(
    state: &AppState,
    user_id: Uuid,
    account_id: Uuid,
) -> Result<(), AuthError> {
    state.repos.privacy().soft_delete_user(user_id).await?;
    state.repos.postgres().revoke_user_refresh_tokens(user_id).await?;
    state.repos.privacy().anonymize_user(user_id).await?;
    state
        .audit(
            Some(account_id),
            Some(&user_id.to_string()),
            "privacy.delete",
            Some("users"),
            None,
            json!({}),
        )
        .await?;
    super::ops::dispatch_webhook(
        state,
        account_id,
        "user.deleted",
        json!({"user_id": user_id}),
    );
    Ok(())
}
