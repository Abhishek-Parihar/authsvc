use async_trait::async_trait;
use uuid::Uuid;

use crate::{
    account::{Account, AccountOption, CreateAccount},
    client::{CreateOAuthClient, OAuthClient},
    membership::{AccountMember, WebsiteMember},
    role::{AuthzCheck, AuthzResult, Permission, Role},
    user::{CreateUser, User},
    website::{CreateWebsite, PortalInfo, Website},
    AuthError,
};

#[async_trait]
pub trait UserRepository: Send + Sync {
    async fn create(&self, user: &CreateUser, password_hash: &str) -> Result<User, AuthError>;
    async fn find_by_email(&self, email: &str) -> Result<Option<User>, AuthError>;
    async fn find_by_id(&self, id: Uuid) -> Result<Option<User>, AuthError>;
    async fn set_locked_until(
        &self,
        user_id: Uuid,
        until: chrono::DateTime<chrono::Utc>,
    ) -> Result<(), AuthError>;
    async fn count_users(&self) -> Result<i64, AuthError>;
}

#[async_trait]
pub trait AccountRepository: Send + Sync {
    async fn find_by_slug(&self, slug: &str) -> Result<Option<Account>, AuthError>;
    async fn find_by_id(&self, id: Uuid) -> Result<Option<Account>, AuthError>;
    async fn create(&self, input: &CreateAccount) -> Result<Account, AuthError>;
    async fn ensure_default(&self) -> Result<Account, AuthError>;
}

#[async_trait]
pub trait WebsiteRepository: Send + Sync {
    async fn find_by_slug(&self, account_id: Uuid, slug: &str) -> Result<Option<Website>, AuthError>;
    async fn find_by_id(&self, id: Uuid) -> Result<Option<Website>, AuthError>;
    async fn create(&self, input: &CreateWebsite) -> Result<Website, AuthError>;
    async fn find_by_client_id(&self, client_id: &str) -> Result<Option<(Website, OAuthClient)>, AuthError>;
}

#[async_trait]
pub trait MembershipRepository: Send + Sync {
    async fn add_account_member(
        &self,
        account_id: Uuid,
        user_id: Uuid,
        role_id: Option<Uuid>,
    ) -> Result<AccountMember, AuthError>;
    async fn list_user_accounts(&self, user_id: Uuid) -> Result<Vec<AccountMember>, AuthError>;
    async fn get_account_member(
        &self,
        account_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<AccountMember>, AuthError>;
    async fn add_website_member(
        &self,
        website_id: Uuid,
        user_id: Uuid,
        role_id: Option<Uuid>,
    ) -> Result<WebsiteMember, AuthError>;
}

#[async_trait]
pub trait ClientRepository: Send + Sync {
    async fn create(
        &self,
        input: &CreateOAuthClient,
        client_id: &str,
        client_secret_hash: Option<&str>,
    ) -> Result<(OAuthClient, Option<String>), AuthError>;
    async fn find_by_client_id(&self, client_id: &str) -> Result<Option<OAuthClient>, AuthError>;
    async fn find_client_id_by_uuid(&self, id: Uuid) -> Result<Option<String>, AuthError>;
}

#[async_trait]
pub trait RoleRepository: Send + Sync {
    async fn list_user_permissions(
        &self,
        user_id: Uuid,
        account_id: Uuid,
        website_id: Option<Uuid>,
    ) -> Result<Vec<Permission>, AuthError>;
    async fn assign_role(&self, user_id: Uuid, role_id: Uuid) -> Result<(), AuthError>;
    async fn list_roles(&self, account_id: Uuid) -> Result<Vec<Role>, AuthError>;
}

#[async_trait]
pub trait RefreshTokenRepository: Send + Sync {
    async fn store(
        &self,
        token_hash: &str,
        user_id: Option<Uuid>,
        client_id: Uuid,
        account_id: Uuid,
        family_id: Uuid,
        expires_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<(), AuthError>;
    async fn consume(
        &self,
        token_hash: &str,
    ) -> Result<Option<RefreshTokenRecord>, AuthError>;
    async fn revoke_family(&self, family_id: Uuid) -> Result<(), AuthError>;
}

#[derive(Debug, Clone)]
pub struct RefreshTokenRecord {
    pub user_id: Option<Uuid>,
    pub client_id: Uuid,
    pub account_id: Uuid,
    pub family_id: Uuid,
    pub revoked: bool,
}

#[async_trait]
pub trait SessionStore: Send + Sync {
    async fn create(&self, session_id: Uuid, user_id: Uuid, ttl_secs: u64) -> Result<(), AuthError>;
    async fn get_user_id(&self, session_id: Uuid) -> Result<Option<Uuid>, AuthError>;
    async fn delete(&self, session_id: Uuid) -> Result<(), AuthError>;
    async fn list_for_user(&self, user_id: Uuid) -> Result<Vec<Uuid>, AuthError>;
}

#[async_trait]
pub trait PolicyEvaluator: Send + Sync {
    async fn check(&self, req: &AuthzCheck) -> Result<AuthzResult, AuthError>;
}

#[async_trait]
pub trait NotificationSender: Send + Sync {
    async fn send_email(&self, to: &str, subject: &str, body: &str) -> Result<(), AuthError>;
    async fn send_sms(&self, to: &str, body: &str) -> Result<(), AuthError>;
}

#[derive(Debug, Clone)]
pub struct WebAuthnCredential {
    pub id: Uuid,
    pub user_id: Uuid,
    pub credential_id: Vec<u8>,
    pub public_key: Vec<u8>,
    pub sign_count: i64,
    pub name: Option<String>,
}

#[async_trait]
pub trait WebAuthnRepository: Send + Sync {
    async fn store_credential(
        &self,
        user_id: Uuid,
        credential_id: &[u8],
        public_key: &[u8],
        name: Option<&str>,
    ) -> Result<Uuid, AuthError>;
    async fn list_credentials(&self, user_id: Uuid) -> Result<Vec<WebAuthnCredential>, AuthError>;
    async fn update_sign_count(&self, id: Uuid, sign_count: i64) -> Result<(), AuthError>;
    async fn find_user_by_email(&self, email: &str) -> Result<Option<User>, AuthError>;
}

#[async_trait]
pub trait OtpStore: Send + Sync {
    async fn store_email_otp(
        &self,
        email: &str,
        code_hash: &str,
        expires_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<(), AuthError>;
    async fn consume_email_otp(&self, email: &str, code_hash: &str) -> Result<bool, AuthError>;
    async fn store_phone_otp(
        &self,
        phone: &str,
        code_hash: &str,
        expires_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<(), AuthError>;
    async fn consume_phone_otp(&self, phone: &str, code_hash: &str) -> Result<bool, AuthError>;
    async fn find_user_id_by_phone(&self, phone: &str) -> Result<Option<Uuid>, AuthError>;
    async fn link_verified_phone(&self, user_id: Uuid, phone: &str) -> Result<(), AuthError>;
}

#[async_trait]
pub trait MfaStore: Send + Sync {
    async fn store_mfa_secret(
        &self,
        user_id: Uuid,
        encrypted: &str,
        recovery_hashes: &[String],
        enable: bool,
    ) -> Result<(), AuthError>;
    async fn enable_mfa(&self, user_id: Uuid) -> Result<(), AuthError>;
    async fn consume_recovery_code(
        &self,
        user_id: Uuid,
        code_hash: &str,
    ) -> Result<bool, AuthError>;
    async fn get_mfa_secret(&self, user_id: Uuid) -> Result<Option<String>, AuthError>;
    async fn store_mfa_challenge(
        &self,
        id: Uuid,
        user_id: Uuid,
        client_id: Uuid,
        expires: chrono::DateTime<chrono::Utc>,
    ) -> Result<(), AuthError>;
    async fn complete_mfa_challenge(&self, id: Uuid) -> Result<Option<(Uuid, Uuid)>, AuthError>;
    async fn disable_mfa(&self, user_id: Uuid) -> Result<(), AuthError>;
}

#[async_trait]
pub trait MagicLinkStore: Send + Sync {
    async fn store_magic_link(
        &self,
        hash: &str,
        email: &str,
        expires: chrono::DateTime<chrono::Utc>,
    ) -> Result<(), AuthError>;
    async fn consume_magic_link(&self, hash: &str) -> Result<Option<String>, AuthError>;
}

#[async_trait]
pub trait OidcFlowStore: Send + Sync {
    #[allow(clippy::too_many_arguments)]
    async fn store_auth_code(
        &self,
        code: &str,
        client_id: Uuid,
        user_id: Uuid,
        redirect_uri: &str,
        code_challenge: &str,
        scopes: &[String],
        expires_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<(), AuthError>;
    async fn consume_auth_code(
        &self,
        code: &str,
        redirect_uri: &str,
        code_verifier: &str,
    ) -> Result<Option<(Uuid, Uuid, Vec<String>)>, AuthError>;
    async fn store_login_state(
        &self,
        state: &str,
        client_id: &str,
        redirect_uri: &str,
        code_challenge: &str,
        scopes: &[String],
        expires_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<(), AuthError>;
    async fn get_login_state(
        &self,
        state: &str,
    ) -> Result<Option<(String, String, String, Vec<String>)>, AuthError>;
}

#[async_trait]
pub trait FederationStore: Send + Sync {
    async fn link_identity(
        &self,
        user_id: Uuid,
        provider: &str,
        subject: &str,
        email: Option<&str>,
    ) -> Result<(), AuthError>;
    async fn find_identity(&self, provider: &str, subject: &str) -> Result<Option<Uuid>, AuthError>;
    async fn store_federation_state(
        &self,
        state: &str,
        account_id: Uuid,
        provider: &str,
        expires: chrono::DateTime<chrono::Utc>,
    ) -> Result<(), AuthError>;
    async fn consume_federation_state(
        &self,
        state: &str,
    ) -> Result<Option<(Uuid, String)>, AuthError>;
}

#[async_trait]
pub trait PortalStore: Send + Sync {
    async fn find_portal_by_domain(&self, domain: &str) -> Result<Option<PortalInfo>, AuthError>;
    async fn list_user_account_options(&self, user_id: Uuid) -> Result<Vec<AccountOption>, AuthError>;
    async fn website_account_id(&self, website_id: Uuid) -> Result<Uuid, AuthError>;
}

#[async_trait]
pub trait SigningKeyStore: Send + Sync {
    /// Persist public key metadata; private key stored encrypted (never plaintext).
    async fn store_signing_key(
        &self,
        kid: &str,
        public_pem: &str,
        encrypted_private_pem: Option<&str>,
    ) -> Result<(), AuthError>;
    /// Returns (kid, public_pem, encrypted_private_pem).
    async fn get_active_signing_key(
        &self,
    ) -> Result<Option<(String, String, Option<String>)>, AuthError>;
    async fn list_signing_keys_for_jwks(
        &self,
        grace_secs: u64,
    ) -> Result<Vec<(String, String)>, AuthError>;
    async fn deactivate_signing_keys(&self) -> Result<(), AuthError>;
}

#[async_trait]
pub trait HealthStore: Send + Sync {
    async fn ping(&self) -> Result<(), AuthError>;
}

#[async_trait]
pub trait AdminStore: Send + Sync {
    async fn create_website(
        &self,
        account_id: Uuid,
        slug: &str,
        name: &str,
        domain: Option<&str>,
    ) -> Result<serde_json::Value, AuthError>;
    async fn list_clients(&self, website_id: Uuid) -> Result<Vec<serde_json::Value>, AuthError>;
    async fn delete_client(&self, id: Uuid) -> Result<(), AuthError>;
    async fn create_role(
        &self,
        account_id: Uuid,
        name: &str,
        description: Option<&str>,
    ) -> Result<Role, AuthError>;
    async fn create_permission(
        &self,
        account_id: Uuid,
        resource: &str,
        action: &str,
    ) -> Result<Permission, AuthError>;
    async fn add_role_inheritance(
        &self,
        child_role_id: Uuid,
        parent_role_id: Uuid,
    ) -> Result<(), AuthError>;
    async fn remove_role_inheritance(
        &self,
        child_role_id: Uuid,
        parent_role_id: Uuid,
    ) -> Result<(), AuthError>;
    async fn create_casbin_rule(
        &self,
        account_id: Uuid,
        ptype: &str,
        v0: Option<&str>,
        v1: Option<&str>,
        v2: Option<&str>,
        v3: Option<&str>,
        v4: Option<&str>,
        v5: Option<&str>,
    ) -> Result<i32, AuthError>;
    async fn delete_casbin_rule(&self, id: i32) -> Result<(), AuthError>;
    async fn list_casbin_rules(
        &self,
        account_id: Uuid,
    ) -> Result<
        Vec<(
            i32,
            String,
            Option<String>,
            Option<String>,
            Option<String>,
            Option<String>,
            Option<String>,
            Option<String>,
        )>,
        AuthError,
    >;
}

#[async_trait]
pub trait ApiKeyStore: Send + Sync {
    async fn create_api_key(
        &self,
        account_id: Uuid,
        name: &str,
        prefix: &str,
        hash: &str,
        scopes: &[String],
        expires_at: Option<chrono::DateTime<chrono::Utc>>,
    ) -> Result<Uuid, AuthError>;
    async fn find_api_key(
        &self,
        hash: &str,
    ) -> Result<Option<(Uuid, Uuid, Vec<String>)>, AuthError>;
    async fn revoke_api_key(&self, id: Uuid) -> Result<(), AuthError>;
}

#[async_trait]
pub trait WebhookStore: Send + Sync {
    async fn create_webhook(
        &self,
        account_id: Uuid,
        url: &str,
        secret: &str,
        events: &[String],
    ) -> Result<Uuid, AuthError>;
    async fn list_webhooks_for_event(
        &self,
        account_id: Uuid,
        event: &str,
    ) -> Result<Vec<(Uuid, String, String)>, AuthError>;
    async fn record_webhook_delivery(
        &self,
        id: Uuid,
        webhook_id: Uuid,
        event: &str,
        status: &str,
        attempts: i32,
        error: Option<&str>,
    ) -> Result<(), AuthError>;
}

#[async_trait]
pub trait AuditStore: Send + Sync {
    async fn audit(
        &self,
        account_id: Option<Uuid>,
        actor: Option<&str>,
        action: &str,
        resource: Option<&str>,
        ip: Option<&str>,
        metadata: serde_json::Value,
    ) -> Result<(), AuthError>;
}

#[async_trait]
pub trait CacheStore: Send + Sync {
    async fn set_json<T>(&self, key: &str, value: &T, ttl_secs: u64) -> Result<(), AuthError>
    where
        T: serde::Serialize + Send + Sync;
    async fn get_json<T>(&self, key: &str) -> Result<Option<T>, AuthError>
    where
        T: serde::de::DeserializeOwned + Send;
    async fn delete_key(&self, key: &str) -> Result<(), AuthError>;
}

/// Field-level encryption for secrets at rest (MFA, webhooks, IdP configs).
#[async_trait]
pub trait DataKeyStore: Send + Sync {
    async fn encrypt(&self, plaintext: &[u8], context: &str) -> Result<Vec<u8>, AuthError>;
    async fn decrypt(&self, ciphertext: &[u8], context: &str) -> Result<Vec<u8>, AuthError>;
}

#[async_trait]
pub trait IdpConfigStore: Send + Sync {
    async fn list_by_account(
        &self,
        account_id: Uuid,
    ) -> Result<Vec<(Uuid, String, bool, serde_json::Value)>, AuthError>;
    async fn get(
        &self,
        account_id: Uuid,
        provider: &str,
    ) -> Result<Option<(Uuid, bool, serde_json::Value)>, AuthError>;
    async fn upsert(
        &self,
        account_id: Uuid,
        provider: &str,
        enabled: bool,
        config: serde_json::Value,
    ) -> Result<Uuid, AuthError>;
    async fn delete(&self, account_id: Uuid, provider: &str) -> Result<(), AuthError>;
}

#[async_trait]
pub trait PrivacyStore: Send + Sync {
    async fn soft_delete_user(&self, user_id: Uuid) -> Result<(), AuthError>;
    async fn anonymize_user(&self, user_id: Uuid) -> Result<(), AuthError>;
    async fn create_export_request(
        &self,
        user_id: Uuid,
        account_id: Uuid,
    ) -> Result<Uuid, AuthError>;
    async fn complete_export_request(
        &self,
        id: Uuid,
        account_id: Uuid,
        artifact: &serde_json::Value,
    ) -> Result<(), AuthError>;
    async fn list_user_identities(&self, user_id: Uuid) -> Result<Vec<serde_json::Value>, AuthError>;
    async fn list_user_audit_events(
        &self,
        user_id: Uuid,
        limit: i64,
    ) -> Result<Vec<serde_json::Value>, AuthError>;
    async fn complete_erasure(&self, user_id: Uuid, account_ids: &[Uuid]) -> Result<(), AuthError>;
}

#[async_trait]
pub trait ScimTokenStore: Send + Sync {
    async fn create_token(
        &self,
        account_id: Uuid,
        name: &str,
        token_hash: &str,
    ) -> Result<Uuid, AuthError>;
    async fn find_account_by_token_hash(
        &self,
        token_hash: &str,
    ) -> Result<Option<Uuid>, AuthError>;
    async fn revoke_token(&self, id: Uuid) -> Result<(), AuthError>;
}

/// Resolved auth context when issuing tokens.
#[derive(Debug, Clone)]
pub struct TokenContext {
    pub account_id: Uuid,
    pub website_id: Uuid,
}
