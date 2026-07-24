use axum::{
    extract::{Query, State},
    http::HeaderMap,
    response::{IntoResponse, Redirect},
    Json,
};
use authsvc_core::{AuthError, AuthzCheck, AuthzResult, SessionStore};
use serde::Deserialize;
use serde_json::{json, Value};
use uuid::Uuid;

use crate::{
    handlers::{auth::extract_bearer_user, ApiError, AppResult, SharedState},
    middleware::{authenticate, AuthContext},
    services::{
        authz::check_authorization,
        oidc_flow::{self, AuthorizeParams},
    },
};

pub async fn openid_configuration(
    State(state): State<SharedState>,
) -> AppResult<Json<Value>> {
    let issuer = state.jwt.issuer();
    Ok(Json(json!({
        "issuer": issuer,
        "authorization_endpoint": format!("{issuer}/oauth/authorize"),
        "token_endpoint": format!("{issuer}/oauth/token"),
        "jwks_uri": format!("{issuer}/.well-known/jwks.json"),
        "revocation_endpoint": format!("{issuer}/oauth/revoke"),
        "introspection_endpoint": format!("{issuer}/oauth/introspect"),
        "userinfo_endpoint": format!("{issuer}/oauth/userinfo"),
        "end_session_endpoint": format!("{issuer}/oauth/logout"),
        "device_authorization_endpoint": format!("{issuer}/oauth/device_authorization"),
        "response_types_supported": ["code"],
        "grant_types_supported": [
            "authorization_code",
            "client_credentials",
            "password",
            "refresh_token",
            "api_key",
            "urn:ietf:params:oauth:grant-type:device_code"
        ],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "token_endpoint_auth_methods_supported": [
            "client_secret_post",
            "client_secret_basic"
        ],
        "scopes_supported": ["openid", "profile", "email", "offline_access"],
        "code_challenge_methods_supported": ["S256"]
    })))
}

pub async fn jwks(State(state): State<SharedState>) -> AppResult<Json<Value>> {
    let jwks = state.jwt.jwks()?;
    Ok(Json(jwks))
}

#[derive(Debug, Deserialize)]
pub struct AuthzCheckRequest {
    pub subject_id: String,
    pub account_id: String,
    pub website_id: Option<String>,
    pub action: String,
    pub resource: String,
    pub context: Option<serde_json::Value>,
}

pub async fn check(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(body): Json<AuthzCheckRequest>,
) -> AppResult<Json<AuthzResult>> {
    let account_id = Uuid::parse_str(&body.account_id)
        .map_err(|_| AuthError::Validation("invalid account_id".into()))?;
    let website_id = body
        .website_id
        .as_deref()
        .map(Uuid::parse_str)
        .transpose()
        .map_err(|_| AuthError::Validation("invalid website_id".into()))?;

    if let Ok(AuthContext::ApiKey { account_id: key_account, .. }) =
        authenticate(&state, &headers).await
    {
        if key_account != account_id {
            return Err(ApiError(AuthError::Forbidden));
        }
    }

    let req = AuthzCheck {
        subject_id: Uuid::parse_str(&body.subject_id)
            .map_err(|_| AuthError::Validation("invalid subject_id".into()))?,
        account_id,
        website_id,
        action: body.action,
        resource: body.resource,
        context: body.context,
    };
    let result = check_authorization(&state, req).await?;
    Ok(Json(result))
}

pub async fn userinfo(
    State(state): State<SharedState>,
    headers: HeaderMap,
) -> AppResult<Json<Value>> {
    let claims = extract_bearer_user(&state, &headers).await?;
    let info = oidc_flow::userinfo(&state, &claims).await?;
    Ok(Json(info))
}

#[derive(Debug, Deserialize)]
pub struct IntrospectRequest {
    pub token: String,
    #[serde(default)]
    pub token_type_hint: Option<String>,
}

pub async fn introspect(
    State(state): State<SharedState>,
    Json(body): Json<IntrospectRequest>,
) -> AppResult<Json<Value>> {
    let _ = body.token_type_hint;
    match state.jwt.validate_access_token(&body.token) {
        Ok(claims) => Ok(Json(json!({
            "active": true,
            "sub": claims.sub,
            "client_id": claims.client_id,
            "scope": claims.scope,
            "exp": claims.exp,
            "iat": claims.iat,
            "iss": claims.iss,
            "account_id": claims.account_id,
            "website_id": claims.website_id
        }))),
        Err(_) => Ok(Json(json!({ "active": false }))),
    }
}

#[derive(Debug, Deserialize)]
pub struct AuthorizeQuery {
    pub client_id: String,
    pub redirect_uri: String,
    pub response_type: String,
    pub scope: Option<String>,
    pub state: Option<String>,
    pub code_challenge: String,
    pub code_challenge_method: Option<String>,
}

pub async fn authorize(
    State(state): State<SharedState>,
    Query(q): Query<AuthorizeQuery>,
) -> AppResult<impl axum::response::IntoResponse> {
    if q.response_type != "code" {
        return Err(ApiError(AuthError::Validation(
            "only response_type=code supported".into(),
        )));
    }
    if q.code_challenge_method.as_deref() != Some("S256") {
        return Err(ApiError(AuthError::Validation(
            "only S256 code challenge supported".into(),
        )));
    }

    let scopes: Vec<String> = q
        .scope
        .unwrap_or_else(|| "openid profile".into())
        .split_whitespace()
        .map(str::to_string)
        .collect();

    let login_state = oidc_flow::start_authorization(
        &state,
        AuthorizeParams {
            client_id: q.client_id,
            redirect_uri: q.redirect_uri,
            code_challenge: q.code_challenge,
            scopes,
        },
    )
    .await?;

    Ok(Redirect::temporary(&format!(
        "{}/login?login_state={}",
        state.config.issuer, login_state
    )))
}

#[derive(Debug, Deserialize)]
pub struct OAuthLoginRequest {
    pub login_state: String,
    pub email: String,
    pub password: String,
}

pub async fn oauth_login(
    State(state): State<SharedState>,
    Json(body): Json<OAuthLoginRequest>,
) -> AppResult<impl axum::response::IntoResponse> {
    let result = crate::services::oidc_flow::complete_browser_login(
        &state,
        &body.login_state,
        &body.email,
        &body.password,
        None,
    )
    .await?;

    match result {
        crate::services::oidc_flow::BrowserLoginResult::Success(success) => {
            let session_id = success.session_id;
            let mut response = Json(json!({
                "redirect": success.redirect,
                "session_id": session_id
            }))
            .into_response();

            let cookie = format!(
                "authsvc_session={session_id}; HttpOnly; Path=/; SameSite=Lax{}",
                if state.config.cookie_secure {
                    "; Secure"
                } else {
                    ""
                }
            );
            response.headers_mut().insert(
                axum::http::header::SET_COOKIE,
                cookie.parse().unwrap(),
            );
            Ok(response)
        }
        crate::services::oidc_flow::BrowserLoginResult::MfaRequired(mfa) => {
            Ok(Json(json!(mfa)).into_response())
        }
        crate::services::oidc_flow::BrowserLoginResult::AccountSelection(selection) => {
            Ok(Json(json!(selection)).into_response())
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct EndSessionQuery {
    pub id_token_hint: Option<String>,
    pub post_logout_redirect_uri: Option<String>,
    pub state: Option<String>,
    pub client_id: Option<String>,
}

pub async fn logout_get(
    State(state): State<SharedState>,
    headers: HeaderMap,
    query: Query<EndSessionQuery>,
) -> AppResult<impl axum::response::IntoResponse> {
    end_session(&state, &headers, Some(query.0)).await
}

pub async fn logout_post(
    State(state): State<SharedState>,
    headers: HeaderMap,
) -> AppResult<impl axum::response::IntoResponse> {
    end_session(&state, &headers, None).await
}

async fn end_session(
    state: &SharedState,
    headers: &HeaderMap,
    query: Option<EndSessionQuery>,
) -> AppResult<impl axum::response::IntoResponse> {
    clear_session_cookie(state, headers).await?;

    if let Some(q) = query {
        if let Some(redirect_uri) = q.post_logout_redirect_uri {
            if let Some(client_id) = q.client_id.as_deref() {
                let client = state
                    .repos
                    .clients()
                    .find_by_client_id(client_id)
                    .await?
                    .ok_or(AuthError::ClientNotFound)?;
                crate::security::redirect_uri::validate_redirect_uri(
                    &client,
                    &redirect_uri,
                    state.config.is_production(),
                )?;
            } else if let Some(hint) = &q.id_token_hint {
                let _ = state.jwt.validate_id_token(hint)?;
            }

            let mut target = redirect_uri;
            if let Some(st) = q.state {
                let sep = if target.contains('?') { '&' } else { '?' };
                target = format!("{target}{sep}state={st}");
            }
            return Ok(Redirect::temporary(&target).into_response());
        }
    }

    Ok(axum::http::StatusCode::NO_CONTENT.into_response())
}

async fn clear_session_cookie(
    state: &SharedState,
    headers: &HeaderMap,
) -> Result<(), AuthError> {
    if let Some(cookie) = headers.get(axum::http::header::COOKIE).and_then(|v| v.to_str().ok()) {
        for part in cookie.split(';') {
            let part = part.trim();
            if let Some(sid) = part.strip_prefix("authsvc_session=") {
                if let Ok(id) = Uuid::parse_str(sid) {
                    SessionStore::delete(&state.sessions, id).await?;
                }
            }
        }
    }
    Ok(())
}
