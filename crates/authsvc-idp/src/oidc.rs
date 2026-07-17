use async_trait::async_trait;
use authsvc_core::AuthError;
use oauth2::{
    basic::BasicClient, AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken, RedirectUrl,
    TokenResponse, TokenUrl,
};
use reqwest::header::USER_AGENT;

use crate::{FederatedUser, IdentityProvider};

pub struct GenericOidcProvider {
    name: String,
    client: BasicClient,
    userinfo_url: String,
}

impl GenericOidcProvider {
    pub fn new(
        name: impl Into<String>,
        auth_url: &str,
        token_url: &str,
        userinfo_url: &str,
        client_id: &str,
        client_secret: &str,
        redirect_uri: &str,
    ) -> Result<Self, AuthError> {
        let client = BasicClient::new(
            ClientId::new(client_id.to_string()),
            Some(ClientSecret::new(client_secret.to_string())),
            AuthUrl::new(auth_url.to_string()).map_err(|e| AuthError::Internal(e.to_string()))?,
            Some(TokenUrl::new(token_url.to_string()).map_err(|e| AuthError::Internal(e.to_string()))?),
        )
        .set_redirect_uri(
            RedirectUrl::new(redirect_uri.to_string()).map_err(|e| AuthError::Internal(e.to_string()))?,
        );
        Ok(Self {
            name: name.into(),
            client,
            userinfo_url: userinfo_url.to_string(),
        })
    }
}

#[async_trait]
impl IdentityProvider for GenericOidcProvider {
    fn name(&self) -> &str {
        &self.name
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
        let profile: serde_json::Value = reqwest::Client::new()
            .get(&self.userinfo_url)
            .header(USER_AGENT, "authsvc")
            .bearer_auth(access)
            .send()
            .await
            .map_err(|e| AuthError::Internal(e.to_string()))?
            .json()
            .await
            .map_err(|e| AuthError::Internal(e.to_string()))?;

        Ok(FederatedUser {
            provider: self.name.clone(),
            subject: profile["sub"]
                .as_str()
                .or_else(|| profile["id"].as_str())
                .unwrap_or_default()
                .to_string(),
            email: profile["email"].as_str().map(str::to_string),
            name: profile["name"].as_str().map(str::to_string),
            email_verified: profile["email_verified"].as_bool().unwrap_or(false),
        })
    }
}
