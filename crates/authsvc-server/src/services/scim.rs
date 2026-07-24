use authsvc_core::AuthError;
use serde_json::{json, Value};
use uuid::Uuid;

use super::state::AppState;
use crate::crypto::password::{hash_password, hash_token};

pub async fn authenticate_scim(
    state: &AppState,
    bearer: &str,
) -> Result<Uuid, AuthError> {
    let hash = hash_token(bearer);
    state
        .repos
        .scim_tokens()
        .find_account_by_token_hash(&hash)
        .await?
        .ok_or(AuthError::Forbidden)
}

pub async fn create_scim_token(
    state: &AppState,
    account_id: Uuid,
    name: &str,
) -> Result<(Uuid, String), AuthError> {
    let token = Uuid::new_v4().to_string();
    let hash = hash_token(&token);
    let id = state
        .repos
        .scim_tokens()
        .create_token(account_id, name, &hash)
        .await?;
    Ok((id, token))
}

pub async fn list_users(state: &AppState, account_id: Uuid) -> Result<Value, AuthError> {
    let rows = state.repos.postgres().list_scim_users(account_id).await?;
    Ok(json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
        "totalResults": rows.len(),
        "Resources": rows,
    }))
}

pub async fn get_user(state: &AppState, account_id: Uuid, user_id: Uuid) -> Result<Value, AuthError> {
    state
        .repos
        .postgres()
        .get_scim_user(account_id, user_id)
        .await?
        .ok_or(AuthError::UserNotFound)
}

pub async fn create_user(
    state: &AppState,
    account_id: Uuid,
    email: &str,
    display_name: Option<&str>,
) -> Result<Value, AuthError> {
    let pwd = Uuid::new_v4().to_string();
    let hash = hash_password(&pwd)?;
    let user = state
        .repos
        .users()
        .create(
            &authsvc_core::user::CreateUser {
                email: email.to_lowercase(),
                password: pwd,
                display_name: display_name.map(str::to_string),
            },
            &hash,
        )
        .await?;
    state
        .repos
        .memberships()
        .add_account_member(account_id, user.id, None)
        .await?;
    super::ops::dispatch_webhook(
        state,
        account_id,
        "user.provisioned",
        json!({"user_id": user.id, "email": user.email}),
    );
    scim_user_resource(&user, account_id)
}

pub async fn delete_user(state: &AppState, account_id: Uuid, user_id: Uuid) -> Result<(), AuthError> {
    super::privacy::delete_user(state, user_id, account_id).await
}

#[derive(Debug, serde::Deserialize)]
pub struct ScimPatchRequest {
    #[serde(default)]
    pub Operations: Vec<ScimPatchOperation>,
}

#[derive(Debug, serde::Deserialize)]
pub struct ScimPatchOperation {
    pub op: String,
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub value: Option<serde_json::Value>,
}

pub async fn patch_user(
    state: &AppState,
    account_id: Uuid,
    user_id: Uuid,
    patch: ScimPatchRequest,
) -> Result<Value, AuthError> {
    for operation in patch.Operations {
        let op = operation.op.to_ascii_lowercase();
        if op != "replace" && op != "add" {
            return Err(AuthError::Validation(format!(
                "unsupported SCIM patch op: {}",
                operation.op
            )));
        }

        match operation.path.as_deref() {
            Some("displayName") => {
                let name = operation
                    .value
                    .as_ref()
                    .and_then(|v| v.as_str())
                    .map(str::to_string);
                state
                    .repos
                    .postgres()
                    .update_scim_user_display_name(account_id, user_id, name.as_deref())
                    .await?;
            }
            Some("active") => {
                let active = operation
                    .value
                    .as_ref()
                    .and_then(|v| v.as_bool())
                    .ok_or_else(|| AuthError::Validation("active must be a boolean".into()))?;
                state
                    .repos
                    .postgres()
                    .set_scim_user_active(account_id, user_id, active)
                    .await?;
            }
            Some(path) => {
                return Err(AuthError::Validation(format!(
                    "unsupported SCIM patch path: {path}"
                )));
            }
            None => {
                if let Some(obj) = operation.value.and_then(|v| v.as_object().cloned()) {
                    if let Some(name) = obj.get("displayName").and_then(|v| v.as_str()) {
                        state
                            .repos
                            .postgres()
                            .update_scim_user_display_name(account_id, user_id, Some(name))
                            .await?;
                    }
                    if let Some(active) = obj.get("active").and_then(|v| v.as_bool()) {
                        state
                            .repos
                            .postgres()
                            .set_scim_user_active(account_id, user_id, active)
                            .await?;
                    }
                }
            }
        }
    }

    get_user(state, account_id, user_id).await
}

pub async fn get_group(state: &AppState, account_id: Uuid, group_id: Uuid) -> Result<Value, AuthError> {
    state
        .repos
        .postgres()
        .get_scim_group(account_id, group_id)
        .await?
        .ok_or(AuthError::NotFound("group".into()))
}

pub async fn patch_group(
    state: &AppState,
    account_id: Uuid,
    group_id: Uuid,
    patch: ScimPatchRequest,
) -> Result<Value, AuthError> {
    for operation in patch.Operations {
        let op = operation.op.to_ascii_lowercase();
        if op != "add" && op != "remove" {
            return Err(AuthError::Validation(format!(
                "unsupported SCIM group patch op: {}",
                operation.op
            )));
        }

        let members = match operation.path.as_deref() {
            Some("members") => operation
                .value
                .as_ref()
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default(),
            Some(path) if path.starts_with("members") => operation
                .value
                .as_ref()
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default(),
            _ => {
                return Err(AuthError::Validation(
                    "group patch only supports members path".into(),
                ));
            }
        };

        for member in members {
            let user_id = member
                .get("value")
                .and_then(|v| v.as_str())
                .ok_or_else(|| AuthError::Validation("member value required".into()))?;
            let user_id = Uuid::parse_str(user_id)
                .map_err(|_| AuthError::Validation("invalid member user id".into()))?;

            if op == "add" {
                state
                    .repos
                    .postgres()
                    .add_scim_group_member(account_id, group_id, user_id)
                    .await?;
            } else {
                state
                    .repos
                    .postgres()
                    .remove_scim_group_member(account_id, group_id, user_id)
                    .await?;
            }
        }
    }

    get_group(state, account_id, group_id).await
}

fn scim_user_resource(user: &authsvc_core::User, account_id: Uuid) -> Result<Value, AuthError> {
    Ok(json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "id": user.id,
        "userName": user.email,
        "displayName": user.display_name,
        "active": user.status == "active",
        "meta": {
            "resourceType": "User",
            "account_id": account_id,
        }
    }))
}

pub async fn list_groups(state: &AppState, account_id: Uuid) -> Result<Value, AuthError> {
    let roles = state.repos.roles().list_roles(account_id).await?;
    let resources: Vec<Value> = roles
        .into_iter()
        .map(|r| {
            json!({
                "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
                "id": r.id,
                "displayName": r.name,
            })
        })
        .collect();
    Ok(json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
        "totalResults": resources.len(),
        "Resources": resources,
    }))
}
