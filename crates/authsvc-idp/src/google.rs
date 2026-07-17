use async_trait::async_trait;
use authsvc_core::AuthError;
use oauth2::{
    basic::BasicClient, AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken, RedirectUrl,
    TokenResponse, TokenUrl,
};
use reqwest::header::USER_AGENT;

use crate::{FederatedUser, IdentityProvider};

pub struct GoogleProvider {
    client: BasicClient,
}

impl GoogleProvider {
    pub fn new(client_id: &str, client_secret: &str, redirect_uri: &str) -> Result<Self, AuthError> {
        let client = BasicClient::new(
            ClientId::new(client_id.to_string()),
            Some(ClientSecret::new(client_secret.to_string())),
            AuthUrl::new("https://accounts.google.com/o/oauth2/v2/auth".into())
                .map_err(|e| AuthError::Internal(e.to_string()))?,
            Some(
                TokenUrl::new("https://oauth2.googleapis.com/token".into())
                    .map_err(|e| AuthError::Internal(e.to_string()))?,
            ),
        )
        .set_redirect_uri(
            RedirectUrl::new(redirect_uri.to_string())
                .map_err(|e| AuthError::Internal(e.to_string()))?,
        );
        Ok(Self { client })
    }
}

#[async_trait]
impl IdentityProvider for GoogleProvider {
    fn name(&self) -> &str {
        "google"
    }

    fn authorization_url(&self, state: &str, _redirect_uri: &str) -> Result<String, AuthError> {
        let (url, _) = self
            .client
            .authorize_url(|| CsrfToken::new(state.to_string()))
            .add_scope(oauth2::Scope::new("openid email profile".into()))
            .url();
        Ok(url.to_string())
    }

    async fn exchange_code(
        &self,
        code: &str,
        _redirect_uri: &str,
    ) -> Result<FederatedUser, AuthError> {
        let token = self
            .client
            .exchange_code(AuthorizationCode::new(code.to_string()))
            .request_async(oauth2::reqwest::async_http_client)
            .await
            .map_err(|e| AuthError::Internal(e.to_string()))?;

        let access = token.access_token().secret();
        let http = reqwest::Client::new();
        let profile: serde_json::Value = http
            .get("https://www.googleapis.com/oauth2/v3/userinfo")
            .header(USER_AGENT, "authsvc")
            .bearer_auth(access)
            .send()
            .await
            .map_err(|e| AuthError::Internal(e.to_string()))?
            .json()
            .await
            .map_err(|e| AuthError::Internal(e.to_string()))?;

        Ok(FederatedUser {
            provider: "google".into(),
            subject: profile["sub"].as_str().unwrap_or_default().to_string(),
            email: profile["email"].as_str().map(str::to_string),
            name: profile["name"].as_str().map(str::to_string),
            email_verified: profile["email_verified"].as_bool().unwrap_or(false),
        })
    }
}
