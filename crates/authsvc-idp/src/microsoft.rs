use authsvc_core::AuthError;

use crate::oidc::GenericOidcProvider;
use crate::IdentityProvider;

pub struct MicrosoftProvider(GenericOidcProvider);

impl MicrosoftProvider {
    pub fn new(
        client_id: &str,
        client_secret: &str,
        redirect_uri: &str,
        tenant: Option<&str>,
    ) -> Result<Self, AuthError> {
        let tenant = tenant.unwrap_or("common");
        let auth_url = format!(
            "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize"
        );
        let token_url = format!("https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token");
        Ok(Self(GenericOidcProvider::new(
            "microsoft",
            &auth_url,
            &token_url,
            "https://graph.microsoft.com/oidc/userinfo",
            client_id,
            client_secret,
            redirect_uri,
        )?))
    }
}

#[async_trait::async_trait]
impl IdentityProvider for MicrosoftProvider {
    fn name(&self) -> &str {
        self.0.name()
    }

    fn authorization_url(&self, state: &str, redirect_uri: &str) -> Result<String, AuthError> {
        self.0.authorization_url(state, redirect_uri)
    }

    async fn exchange_code(
        &self,
        code: &str,
        redirect_uri: &str,
    ) -> Result<crate::FederatedUser, AuthError> {
        self.0.exchange_code(code, redirect_uri).await
    }
}
