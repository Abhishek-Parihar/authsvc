use authsvc_core::AuthError;
use chrono::{Duration, Utc};
use uuid::Uuid;

use super::{admin::default_account_id, auth, state::AppState};
use crate::crypto::signing_keys::resolve_active_private_pem;

pub async fn idp_metadata(state: &AppState) -> Result<String, AuthError> {
    let issuer = state.config.issuer.trim_end_matches('/');
    let (_, public_pem, _) = state
        .repos
        .signing_keys()
        .get_active_signing_key()
        .await?
        .ok_or_else(|| AuthError::Internal("no active signing key for SAML IdP metadata".into()))?;
    Ok(authsvc_idp::saml_idp::idp_metadata_xml(
        issuer,
        &format!("{issuer}/saml/idp/sso"),
        &format!("{issuer}/saml/idp/slo"),
        &public_pem,
    ))
}

pub async fn begin_sso(
    state: &AppState,
    saml_request_b64: &str,
    relay_state: Option<&str>,
) -> Result<Uuid, AuthError> {
    let account_id = default_account_id(state).await?;
    let xml = authsvc_idp::saml_idp::decode_saml_request_param(saml_request_b64)?;
    let parsed = authsvc_idp::saml_idp::parse_authn_request(&xml)?;

    let sp = state
        .repos
        .postgres()
        .find_saml_sp_by_entity(account_id, &parsed.issuer)
        .await?
        .ok_or_else(|| AuthError::Validation("unknown SAML service provider".into()))?;

    if sp.acs_url != parsed.acs_url {
        return Err(AuthError::Validation("ACS URL mismatch for service provider".into()));
    }

    if sp.want_authn_requests_signed {
        let cert = sp
            .sp_cert_pem
            .as_deref()
            .ok_or_else(|| AuthError::Validation("SP certificate required".into()))?;
        authsvc_idp::saml_idp::verify_authn_request_signature(&xml, cert)?;
    }

    let pending_id = Uuid::new_v4();
    state
        .repos
        .postgres()
        .store_saml_pending_authn(
            pending_id,
            account_id,
            sp.id,
            &parsed.id,
            relay_state,
            &parsed.acs_url,
            &parsed.issuer,
            Utc::now() + Duration::minutes(10),
        )
        .await?;

    Ok(pending_id)
}

pub async fn complete_sso(
    state: &AppState,
    pending_id: Uuid,
    email: &str,
    password: &str,
    ip: Option<&str>,
) -> Result<String, AuthError> {
    let user = auth::verify_user_password(state, email, password, ip).await?;
    let pending = state
        .repos
        .postgres()
        .consume_saml_pending_authn(pending_id)
        .await?
        .ok_or(AuthError::InvalidToken)?;

    let private_pem = resolve_active_private_pem(
        state.repos.signing_keys(),
        &state.data_keys,
        state.config.jwt_private_key_pem.as_deref(),
    )
    .await?;

    let issuer = state.config.issuer.trim_end_matches('/');
    let name_id = user.email.clone();
    let response_xml = authsvc_idp::saml_idp::build_authn_response(
        issuer,
        &pending.sp_entity_id,
        &pending.acs_url,
        &pending.request_id,
        &name_id,
        &user.email,
        user.display_name.as_deref(),
        &private_pem,
    )?;

    let encoded = authsvc_idp::saml_idp::encode_response_for_post(&response_xml);
    Ok(authsvc_idp::saml_idp::post_binding_html(
        &pending.acs_url,
        &encoded,
        pending.relay_state.as_deref(),
    ))
}

pub async fn create_saml_sp(
    state: &AppState,
    account_id: Uuid,
    name: &str,
    entity_id: &str,
    acs_url: &str,
    slo_url: Option<&str>,
    sp_cert_pem: Option<&str>,
    want_signed: bool,
) -> Result<crate::stores::extended::SamlServiceProvider, AuthError> {
    crate::security::webhook_url::validate_webhook_url(acs_url, state.config.is_production())?;
    if let Some(slo) = slo_url {
        crate::security::webhook_url::validate_webhook_url(slo, state.config.is_production())?;
    }
    state
        .repos
        .postgres()
        .create_saml_sp(
            account_id,
            name,
            entity_id,
            acs_url,
            slo_url,
            sp_cert_pem,
            want_signed,
        )
        .await
}

pub async fn list_saml_sps(
    state: &AppState,
    account_id: Uuid,
) -> Result<Vec<crate::stores::extended::SamlServiceProvider>, AuthError> {
    state.repos.postgres().list_saml_sps(account_id).await
}

pub async fn delete_saml_sp(state: &AppState, account_id: Uuid, id: Uuid) -> Result<(), AuthError> {
    state.repos.postgres().delete_saml_sp(account_id, id).await
}

pub async fn search_users(state: &AppState, query: &str) -> Result<Vec<serde_json::Value>, AuthError> {
    if query.len() < 2 {
        return Err(AuthError::Validation("search query too short".into()));
    }
    state
        .repos
        .postgres()
        .search_users_by_email(query, 50)
        .await
}

pub async fn list_audit_events(
    state: &AppState,
    account_id: Uuid,
    limit: i64,
) -> Result<Vec<serde_json::Value>, AuthError> {
    state
        .repos
        .postgres()
        .list_account_audit_events(account_id, limit.min(200))
        .await
}
