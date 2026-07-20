use async_trait::async_trait;
use authsvc_core::{
    AdminStore, ApiKeyStore, AuditStore, AuthError, FederationStore, HealthStore, IdpConfigStore,
    MagicLinkStore, MfaStore, OidcFlowStore, OtpStore, PortalStore, PrivacyStore, ScimTokenStore,
    SigningKeyStore, User, UserRepository, WebAuthnCredential, WebAuthnRepository, WebhookStore,
};
use chrono::{DateTime, Utc};
use uuid::Uuid;

use super::PostgresStore;

#[async_trait]
impl OtpStore for PostgresStore {
    async fn store_email_otp(
        &self,
        email: &str,
        code_hash: &str,
        expires_at: DateTime<Utc>,
    ) -> Result<(), AuthError> {
        self.store_email_otp(email, code_hash, expires_at).await
    }

    async fn consume_email_otp(&self, email: &str, code_hash: &str) -> Result<bool, AuthError> {
        self.consume_email_otp(email, code_hash).await
    }

    async fn store_phone_otp(
        &self,
        phone: &str,
        code_hash: &str,
        expires_at: DateTime<Utc>,
    ) -> Result<(), AuthError> {
        self.store_phone_otp(phone, code_hash, expires_at).await
    }

    async fn consume_phone_otp(&self, phone: &str, code_hash: &str) -> Result<bool, AuthError> {
        self.consume_phone_otp(phone, code_hash).await
    }

    async fn find_user_id_by_phone(&self, phone: &str) -> Result<Option<Uuid>, AuthError> {
        self.find_user_id_by_phone(phone).await
    }

    async fn link_verified_phone(&self, user_id: Uuid, phone: &str) -> Result<(), AuthError> {
        self.link_verified_phone(user_id, phone).await
    }
}

#[async_trait]
impl MfaStore for PostgresStore {
    async fn store_mfa_secret(
        &self,
        user_id: Uuid,
        encrypted: &str,
        recovery_hashes: &[String],
    ) -> Result<(), AuthError> {
        self.store_mfa_secret(user_id, encrypted, recovery_hashes).await
    }

    async fn get_mfa_secret(&self, user_id: Uuid) -> Result<Option<String>, AuthError> {
        self.get_mfa_secret(user_id).await
    }

    async fn store_mfa_challenge(
        &self,
        id: Uuid,
        user_id: Uuid,
        client_id: Uuid,
        expires: DateTime<Utc>,
    ) -> Result<(), AuthError> {
        self.store_mfa_challenge(id, user_id, client_id, expires).await
    }

    async fn complete_mfa_challenge(&self, id: Uuid) -> Result<Option<(Uuid, Uuid)>, AuthError> {
        self.complete_mfa_challenge(id).await
    }

    async fn disable_mfa(&self, user_id: Uuid) -> Result<(), AuthError> {
        self.disable_mfa(user_id).await
    }
}

#[async_trait]
impl MagicLinkStore for PostgresStore {
    async fn store_magic_link(
        &self,
        hash: &str,
        email: &str,
        expires: DateTime<Utc>,
    ) -> Result<(), AuthError> {
        self.store_magic_link(hash, email, expires).await
    }

    async fn consume_magic_link(&self, hash: &str) -> Result<Option<String>, AuthError> {
        self.consume_magic_link(hash).await
    }
}

#[async_trait]
impl OidcFlowStore for PostgresStore {
    async fn store_auth_code(
        &self,
        code: &str,
        client_id: Uuid,
        user_id: Uuid,
        redirect_uri: &str,
        code_challenge: &str,
        scopes: &[String],
        expires_at: DateTime<Utc>,
    ) -> Result<(), AuthError> {
        self.store_auth_code(
            code,
            client_id,
            user_id,
            redirect_uri,
            code_challenge,
            scopes,
            expires_at,
        )
        .await
    }

    async fn consume_auth_code(
        &self,
        code: &str,
        redirect_uri: &str,
        code_verifier: &str,
    ) -> Result<Option<(Uuid, Uuid, Vec<String>)>, AuthError> {
        self.consume_auth_code(code, redirect_uri, code_verifier).await
    }

    async fn store_login_state(
        &self,
        state: &str,
        client_id: &str,
        redirect_uri: &str,
        code_challenge: &str,
        scopes: &[String],
        expires_at: DateTime<Utc>,
    ) -> Result<(), AuthError> {
        self.store_login_state(state, client_id, redirect_uri, code_challenge, scopes, expires_at)
            .await
    }

    async fn get_login_state(
        &self,
        state: &str,
    ) -> Result<Option<(String, String, String, Vec<String>)>, AuthError> {
        self.get_login_state(state).await
    }
}

#[async_trait]
impl FederationStore for PostgresStore {
    async fn link_identity(
        &self,
        user_id: Uuid,
        provider: &str,
        subject: &str,
        email: Option<&str>,
    ) -> Result<(), AuthError> {
        self.link_identity(user_id, provider, subject, email).await
    }

    async fn find_identity(&self, provider: &str, subject: &str) -> Result<Option<Uuid>, AuthError> {
        self.find_identity(provider, subject).await
    }

    async fn store_federation_state(
        &self,
        state: &str,
        account_id: Uuid,
        provider: &str,
        expires: DateTime<Utc>,
    ) -> Result<(), AuthError> {
        self.store_federation_state(state, account_id, provider, expires)
            .await
    }

    async fn consume_federation_state(
        &self,
        state: &str,
    ) -> Result<Option<(Uuid, String)>, AuthError> {
        self.consume_federation_state(state).await
    }
}

#[async_trait]
impl PortalStore for PostgresStore {
    async fn find_portal_by_domain(
        &self,
        domain: &str,
    ) -> Result<Option<authsvc_core::PortalInfo>, AuthError> {
        self.find_portal_by_domain(domain).await
    }

    async fn list_user_account_options(
        &self,
        user_id: Uuid,
    ) -> Result<Vec<authsvc_core::AccountOption>, AuthError> {
        self.list_user_account_options(user_id).await
    }

    async fn website_account_id(&self, website_id: Uuid) -> Result<Uuid, AuthError> {
        PostgresStore::website_account_id(self, website_id).await
    }
}

#[async_trait]
impl SigningKeyStore for PostgresStore {
    async fn store_signing_key(
        &self,
        kid: &str,
        private_pem: &str,
        public_pem: &str,
    ) -> Result<(), AuthError> {
        self.store_signing_key(kid, private_pem, public_pem).await
    }

    async fn get_active_signing_key(&self) -> Result<Option<(String, String, String)>, AuthError> {
        self.get_active_signing_key().await
    }

    async fn list_signing_keys_for_jwks(
        &self,
        grace_secs: u64,
    ) -> Result<Vec<(String, String)>, AuthError> {
        self.list_signing_keys_for_jwks(grace_secs).await
    }

    async fn deactivate_signing_keys(&self) -> Result<(), AuthError> {
        self.deactivate_signing_keys().await
    }
}

#[async_trait]
impl HealthStore for PostgresStore {
    async fn ping(&self) -> Result<(), AuthError> {
        PostgresStore::ping(self).await
    }
}

#[async_trait]
impl AdminStore for PostgresStore {
    async fn create_website(
        &self,
        account_id: Uuid,
        slug: &str,
        name: &str,
        domain: Option<&str>,
    ) -> Result<serde_json::Value, AuthError> {
        self.create_website(account_id, slug, name, domain).await
    }

    async fn list_clients(&self, website_id: Uuid) -> Result<Vec<serde_json::Value>, AuthError> {
        self.list_clients(website_id).await
    }

    async fn delete_client(&self, id: Uuid) -> Result<(), AuthError> {
        self.delete_client(id).await
    }

    async fn create_role(
        &self,
        account_id: Uuid,
        name: &str,
        description: Option<&str>,
    ) -> Result<authsvc_core::Role, AuthError> {
        self.create_role(account_id, name, description).await
    }

    async fn create_permission(
        &self,
        account_id: Uuid,
        resource: &str,
        action: &str,
    ) -> Result<authsvc_core::Permission, AuthError> {
        self.create_permission(account_id, resource, action).await
    }

    async fn add_role_inheritance(
        &self,
        child_role_id: Uuid,
        parent_role_id: Uuid,
    ) -> Result<(), AuthError> {
        self.add_role_inheritance(child_role_id, parent_role_id).await
    }

    async fn remove_role_inheritance(
        &self,
        child_role_id: Uuid,
        parent_role_id: Uuid,
    ) -> Result<(), AuthError> {
        self.remove_role_inheritance(child_role_id, parent_role_id).await
    }

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
    ) -> Result<i32, AuthError> {
        self.create_casbin_rule(account_id, ptype, v0, v1, v2, v3, v4, v5)
            .await
    }

    async fn delete_casbin_rule(&self, id: i32) -> Result<(), AuthError> {
        self.delete_casbin_rule(id).await
    }

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
    > {
        self.list_casbin_rules(account_id).await
    }
}

#[async_trait]
impl ApiKeyStore for PostgresStore {
    async fn create_api_key(
        &self,
        account_id: Uuid,
        name: &str,
        prefix: &str,
        hash: &str,
        scopes: &[String],
        expires_at: Option<DateTime<Utc>>,
    ) -> Result<Uuid, AuthError> {
        self.create_api_key(account_id, name, prefix, hash, scopes, expires_at)
            .await
    }

    async fn find_api_key(
        &self,
        hash: &str,
    ) -> Result<Option<(Uuid, Uuid, Vec<String>)>, AuthError> {
        self.find_api_key(hash).await
    }

    async fn revoke_api_key(&self, id: Uuid) -> Result<(), AuthError> {
        self.revoke_api_key(id).await
    }
}

#[async_trait]
impl WebhookStore for PostgresStore {
    async fn create_webhook(
        &self,
        account_id: Uuid,
        url: &str,
        secret: &str,
        events: &[String],
    ) -> Result<Uuid, AuthError> {
        self.create_webhook(account_id, url, secret, events).await
    }

    async fn list_webhooks_for_event(
        &self,
        account_id: Uuid,
        event: &str,
    ) -> Result<Vec<(Uuid, String, String)>, AuthError> {
        self.list_webhooks_for_event(account_id, event).await
    }

    async fn record_webhook_delivery(
        &self,
        id: Uuid,
        webhook_id: Uuid,
        event: &str,
        status: &str,
        attempts: i32,
        error: Option<&str>,
    ) -> Result<(), AuthError> {
        self.record_webhook_delivery(id, webhook_id, event, status, attempts, error)
            .await
    }
}

#[async_trait]
impl AuditStore for PostgresStore {
    async fn audit(
        &self,
        account_id: Option<Uuid>,
        actor: Option<&str>,
        action: &str,
        resource: Option<&str>,
        ip: Option<&str>,
        metadata: serde_json::Value,
    ) -> Result<(), AuthError> {
        self.audit(account_id, actor, action, resource, ip, metadata)
            .await
    }
}

#[async_trait]
impl IdpConfigStore for PostgresStore {
    async fn list_by_account(
        &self,
        account_id: Uuid,
    ) -> Result<Vec<(Uuid, String, bool, serde_json::Value)>, AuthError> {
        self.list_idp_configs(account_id).await
    }

    async fn get(
        &self,
        account_id: Uuid,
        provider: &str,
    ) -> Result<Option<(Uuid, bool, serde_json::Value)>, AuthError> {
        self.get_idp_config(account_id, provider).await
    }

    async fn upsert(
        &self,
        account_id: Uuid,
        provider: &str,
        enabled: bool,
        config: serde_json::Value,
    ) -> Result<Uuid, AuthError> {
        self.upsert_idp_config(account_id, provider, enabled, config)
            .await
    }

    async fn delete(&self, account_id: Uuid, provider: &str) -> Result<(), AuthError> {
        self.delete_idp_config(account_id, provider).await
    }
}

#[async_trait]
impl PrivacyStore for PostgresStore {
    async fn soft_delete_user(&self, user_id: Uuid) -> Result<(), AuthError> {
        self.soft_delete_user(user_id).await
    }

    async fn anonymize_user(&self, user_id: Uuid) -> Result<(), AuthError> {
        self.anonymize_user(user_id).await
    }

    async fn create_export_request(
        &self,
        user_id: Uuid,
        account_id: Uuid,
    ) -> Result<Uuid, AuthError> {
        self.create_export_request(user_id, account_id).await
    }

    async fn complete_export_request(
        &self,
        id: Uuid,
        artifact: &serde_json::Value,
    ) -> Result<(), AuthError> {
        self.complete_export_request(id, artifact).await
    }

    async fn list_user_identities(&self, user_id: Uuid) -> Result<Vec<serde_json::Value>, AuthError> {
        self.list_user_identities(user_id).await
    }

    async fn list_user_audit_events(
        &self,
        user_id: Uuid,
        limit: i64,
    ) -> Result<Vec<serde_json::Value>, AuthError> {
        self.list_user_audit_events(user_id, limit).await
    }
}

#[async_trait]
impl ScimTokenStore for PostgresStore {
    async fn create_token(
        &self,
        account_id: Uuid,
        name: &str,
        token_hash: &str,
    ) -> Result<Uuid, AuthError> {
        self.create_scim_token(account_id, name, token_hash).await
    }

    async fn find_account_by_token_hash(
        &self,
        token_hash: &str,
    ) -> Result<Option<Uuid>, AuthError> {
        self.find_scim_account_by_token_hash(token_hash).await
    }

    async fn revoke_token(&self, id: Uuid) -> Result<(), AuthError> {
        self.revoke_scim_token(id).await
    }
}

#[async_trait]
impl WebAuthnRepository for PostgresStore {
    async fn store_credential(
        &self,
        user_id: Uuid,
        credential_id: &[u8],
        public_key: &[u8],
        name: Option<&str>,
    ) -> Result<Uuid, AuthError> {
        self.store_webauthn_credential(user_id, credential_id, public_key, name)
            .await
    }

    async fn list_credentials(&self, user_id: Uuid) -> Result<Vec<WebAuthnCredential>, AuthError> {
        self.list_webauthn_credentials(user_id).await
    }

    async fn update_sign_count(&self, id: Uuid, sign_count: i64) -> Result<(), AuthError> {
        self.update_webauthn_sign_count(id, sign_count).await
    }

    async fn find_user_by_email(&self, email: &str) -> Result<Option<User>, AuthError> {
        UserRepository::find_by_email(self, email).await
    }
}
