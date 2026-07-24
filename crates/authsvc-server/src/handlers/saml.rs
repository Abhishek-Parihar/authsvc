use axum::{
    extract::{Query, State},
    response::{IntoResponse, Response},
    Json,
};
use serde::Deserialize;
use authsvc_idp::IdentityProvider;
use uuid::Uuid;

use crate::{
    handlers::{AppResult, SharedState},
    services::{admin::default_account_id, federation},
};

#[derive(Debug, Deserialize)]
pub struct SamlCallbackQuery {
    pub SAMLResponse: String,
    pub RelayState: Option<String>,
    pub client_id: String,
}

#[derive(Debug, Deserialize)]
pub struct SamlSloQuery {
    pub SAMLRequest: Option<String>,
    pub SAMLResponse: Option<String>,
    pub RelayState: Option<String>,
}

pub async fn saml_metadata(State(state): State<SharedState>) -> AppResult<impl IntoResponse> {
    let account_id = default_account_id(&state).await?;
    let config = state
        .repos
        .idp_configs()
        .get(account_id, "saml")
        .await?
        .ok_or(authsvc_core::AuthError::NotFound("saml".into()))?;
    let provider = authsvc_idp::saml::SamlProvider::from_config(&config.2, &state.config.issuer)?;
    let acs = format!("{}/saml/acs", state.config.issuer);
    Ok((
        [("content-type", "application/xml")],
        provider.metadata_xml(&acs),
    ))
}

pub async fn saml_login(
    State(state): State<SharedState>,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> AppResult<impl IntoResponse> {
    let account_id = default_account_id(&state).await?;
    let provider_name = params.get("provider").map(String::as_str).unwrap_or("saml");
    let (_, _, config) = state
        .repos
        .idp_configs()
        .get(account_id, provider_name)
        .await?
        .ok_or(authsvc_core::AuthError::NotFound(provider_name.into()))?;
    let provider = authsvc_idp::saml::SamlProvider::from_config(&config, &state.config.issuer)?;
    let state_param = Uuid::new_v4().to_string();
    state
        .repos
        .federation()
        .store_federation_state(
            &state_param,
            account_id,
            provider_name,
            chrono::Utc::now() + chrono::Duration::minutes(10),
        )
        .await?;
    let url = provider.authorization_url(&state_param, "")?;
    Ok(axum::response::Redirect::temporary(&url))
}

pub async fn saml_acs(
    State(state): State<SharedState>,
    axum::Form(form): axum::Form<SamlCallbackQuery>,
) -> AppResult<impl IntoResponse> {
    let relay = form.RelayState.as_deref().unwrap_or("");
    let (federation_state, request_id) = authsvc_idp::saml::split_relay_state(relay);
    let tokens = federation::federation_callback(
        &state,
        federation_state,
        &form.SAMLResponse,
        &form.client_id,
        request_id,
    )
    .await?;
    Ok(Json(tokens))
}

pub async fn saml_slo(
    State(state): State<SharedState>,
    Query(params): Query<SamlSloQuery>,
) -> AppResult<Response> {
    let account_id = default_account_id(&state).await?;
    let config = state
        .repos
        .idp_configs()
        .get(account_id, "saml")
        .await?
        .ok_or(authsvc_core::AuthError::NotFound("saml".into()))?;
    let provider = authsvc_idp::saml::SamlProvider::from_config(&config.2, &state.config.issuer)?;

    if let Some(request) = params.SAMLRequest.as_deref() {
        let name_id = provider.parse_logout_request(request)?;
        let request_id = extract_saml_id(request)?;
        let response_xml = provider.build_logout_response(
            &request_id,
            "urn:oasis:names:tc:SAML:2.0:status:Success",
        )?;
        let _ = name_id;
        return Ok((
            [("content-type", "application/xml")],
            response_xml,
        )
            .into_response());
    }

    if let Some(response) = params.SAMLResponse.as_deref() {
        provider.parse_logout_response(response)?;
        let _ = params.RelayState;
        return Ok(Json(serde_json::json!({"status": "logged_out"})).into_response());
    }

    Err(authsvc_core::AuthError::Validation(
        "SAMLRequest or SAMLResponse required".into(),
    )
    .into())
}

pub async fn saml_logout(
    State(state): State<SharedState>,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> AppResult<impl IntoResponse> {
    let account_id = default_account_id(&state).await?;
    let provider_name = params.get("provider").map(String::as_str).unwrap_or("saml");
    let name_id = params
        .get("name_id")
        .ok_or(authsvc_core::AuthError::Validation("name_id required".into()))?;
    let (_, _, config) = state
        .repos
        .idp_configs()
        .get(account_id, provider_name)
        .await?
        .ok_or(authsvc_core::AuthError::NotFound(provider_name.into()))?;
    let provider = authsvc_idp::saml::SamlProvider::from_config(&config, &state.config.issuer)?;
    let session_index = params.get("session_index").map(String::as_str);
    let relay_state = Uuid::new_v4().to_string();
    let url = provider.logout_redirect_url(name_id, session_index, &relay_state)?;
    Ok(axum::response::Redirect::temporary(&url))
}

fn extract_saml_id(encoded: &str) -> Result<String, authsvc_core::AuthError> {
    let xml = authsvc_idp::saml_authn_request::decode_redirect_saml_message(encoded)
        .map_err(|e| authsvc_core::AuthError::Validation(e.to_string()))?;
    let pattern = "ID=\"";
    let start = xml
        .find(pattern)
        .ok_or_else(|| authsvc_core::AuthError::Validation("SAMLRequest missing ID".into()))?
        + pattern.len();
    let rest = &xml[start..];
    let end = rest
        .find('"')
        .ok_or_else(|| authsvc_core::AuthError::Validation("SAMLRequest missing ID".into()))?;
    Ok(rest[..end].to_string())
}
