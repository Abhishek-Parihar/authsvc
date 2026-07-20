use authsvc_core::AuthError;
use serde_json::Value;
use std::sync::Arc;
use uuid::Uuid;

use super::state::AppState;
use crate::crypto::secrets::{decrypt_string, encrypt_string};

const IDP_CONTEXT: &str = "idp_config";

pub async fn list_idp_configs(
    state: &AppState,
    account_id: Uuid,
) -> Result<Vec<(Uuid, String, bool, Value)>, AuthError> {
    state.repos.idp_configs().list_by_account(account_id).await
}

pub async fn upsert_idp_config(
    state: &AppState,
    account_id: Uuid,
    provider: &str,
    enabled: bool,
    mut config: Value,
) -> Result<Uuid, AuthError> {
    if let Some(secret) = config.get("client_secret").and_then(|v| v.as_str()) {
        let enc = encrypt_string(&state.data_keys, IDP_CONTEXT, secret).await?;
        config["client_secret_enc"] = serde_json::Value::String(enc);
        if let Some(obj) = config.as_object_mut() {
            obj.remove("client_secret");
        }
    }
    state
        .repos
        .idp_configs()
        .upsert(account_id, provider, enabled, config)
        .await
}

pub async fn delete_idp_config(
    state: &AppState,
    account_id: Uuid,
    provider: &str,
) -> Result<(), AuthError> {
    state.repos.idp_configs().delete(account_id, provider).await
}

pub async fn resolve_oidc_provider(
    state: &AppState,
    account_id: Uuid,
    provider: &str,
    redirect_uri: &str,
) -> Result<Arc<dyn authsvc_idp::IdentityProvider>, AuthError> {
    let Some((_, enabled, mut config)) = state
        .repos
        .idp_configs()
        .get(account_id, provider)
        .await?
    else {
        return state.idp_registry.get(provider);
    };
    if !enabled {
        return Err(AuthError::NotFound(provider.into()));
    }
    if config.get("type").and_then(|v| v.as_str()) == Some("saml") {
        return Err(AuthError::Validation("use SAML endpoints for SAML IdP".into()));
    }
    if let Some(enc) = config.get("client_secret_enc").and_then(|v| v.as_str()) {
        let secret = decrypt_string(&state.data_keys, IDP_CONTEXT, enc).await?;
        config["client_secret"] = serde_json::Value::String(secret);
    }
    let idp = authsvc_idp::oidc::GenericOidcProvider::from_config(&config, redirect_uri)?;
    Ok(Arc::new(idp))
}
