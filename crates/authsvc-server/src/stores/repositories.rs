use std::sync::Arc;

use authsvc_core::{
    AccountRepository, AdminStore, ApiKeyStore, AuditStore, ClientRepository, FederationStore,
    HealthStore, IdpConfigStore, MagicLinkStore, MembershipRepository, MfaStore, OidcFlowStore,
    OtpStore, PortalStore, PrivacyStore, RefreshTokenRepository, RoleRepository, ScimTokenStore,
    SigningKeyStore, UserRepository, WebAuthnRepository, WebsiteRepository, WebhookStore,
};

use super::PostgresStore;

/// Typed accessors for domain persistence behind trait boundaries.
#[derive(Clone)]
pub struct Repositories {
    postgres: Arc<PostgresStore>,
}

impl Repositories {
    pub fn new(store: PostgresStore) -> Self {
        Self {
            postgres: Arc::new(store),
        }
    }

    pub(crate) fn postgres(&self) -> &PostgresStore {
        &self.postgres
    }

    pub fn users(&self) -> &dyn UserRepository {
        self.postgres.as_ref()
    }

    pub fn accounts(&self) -> &dyn AccountRepository {
        self.postgres.as_ref()
    }

    pub fn websites(&self) -> &dyn WebsiteRepository {
        self.postgres.as_ref()
    }

    pub fn memberships(&self) -> &dyn MembershipRepository {
        self.postgres.as_ref()
    }

    pub fn clients(&self) -> &dyn ClientRepository {
        self.postgres.as_ref()
    }

    pub fn roles(&self) -> &dyn RoleRepository {
        self.postgres.as_ref()
    }

    pub fn webauthn(&self) -> &dyn WebAuthnRepository {
        self.postgres.as_ref()
    }

    pub fn otp(&self) -> &dyn OtpStore {
        self.postgres.as_ref()
    }

    pub fn mfa(&self) -> &dyn MfaStore {
        self.postgres.as_ref()
    }

    pub fn magic_link(&self) -> &dyn MagicLinkStore {
        self.postgres.as_ref()
    }

    pub fn oidc(&self) -> &dyn OidcFlowStore {
        self.postgres.as_ref()
    }

    pub fn federation(&self) -> &dyn FederationStore {
        self.postgres.as_ref()
    }

    pub fn portal(&self) -> &dyn PortalStore {
        self.postgres.as_ref()
    }

    pub fn signing_keys(&self) -> &dyn SigningKeyStore {
        self.postgres.as_ref()
    }

    pub fn refresh_tokens(&self) -> &dyn RefreshTokenRepository {
        self.postgres.as_ref()
    }

    pub fn health(&self) -> &dyn HealthStore {
        self.postgres.as_ref()
    }

    pub fn admin(&self) -> &dyn AdminStore {
        self.postgres.as_ref()
    }

    pub fn api_keys(&self) -> &dyn ApiKeyStore {
        self.postgres.as_ref()
    }

    pub fn webhooks(&self) -> &dyn WebhookStore {
        self.postgres.as_ref()
    }

    pub fn audit(&self) -> &dyn AuditStore {
        self.postgres.as_ref()
    }

    pub fn idp_configs(&self) -> &dyn IdpConfigStore {
        self.postgres.as_ref()
    }

    pub fn privacy(&self) -> &dyn PrivacyStore {
        self.postgres.as_ref()
    }

    pub fn scim_tokens(&self) -> &dyn ScimTokenStore {
        self.postgres.as_ref()
    }
}
