use authsvc_core::{account::Account, AccountOption, AuthError, Permission, PortalInfo, Role};
use chrono::{DateTime, Utc};
use sqlx::Row;
use uuid::Uuid;

use super::PostgresStore;

impl PostgresStore {
    // --- Accounts ---
    pub async fn create_account(&self, slug: &str, name: &str) -> Result<Account, AuthError> {
        let id = Uuid::new_v4();
        sqlx::query("INSERT INTO accounts (id, slug, name) VALUES ($1, $2, $3)")
            .bind(id)
            .bind(slug)
            .bind(name)
            .execute(self.pool())
            .await
            .map_err(|e| AuthError::Internal(e.to_string()))?;
        Ok(Account {
            id,
            slug: slug.to_string(),
            name: name.to_string(),
            created_at: Utc::now(),
        })
    }

    pub async fn create_website(
        &self,
        account_id: Uuid,
        slug: &str,
        name: &str,
        domain: Option<&str>,
    ) -> Result<serde_json::Value, AuthError> {
        let id = Uuid::new_v4();
        let now = Utc::now();
        sqlx::query(
            "INSERT INTO websites (id, account_id, slug, name, domain, created_at) VALUES ($1,$2,$3,$4,$5,$6)",
        )
        .bind(id)
        .bind(account_id)
        .bind(slug)
        .bind(name)
        .bind(domain)
        .bind(now)
        .execute(self.pool())
        .await
        .map_err(|e| AuthError::Internal(e.to_string()))?;
        Ok(serde_json::json!({
            "id": id,
            "account_id": account_id,
            "slug": slug,
            "name": name,
            "domain": domain,
            "created_at": now,
        }))
    }

    // --- OAuth clients list/delete ---
    pub async fn list_clients(&self, website_id: Uuid) -> Result<Vec<serde_json::Value>, AuthError> {
        let rows = sqlx::query(
            "SELECT id, client_id, name, client_type, grant_types, scopes, created_at
             FROM oauth_clients WHERE website_id = $1",
        )
        .bind(website_id)
        .fetch_all(self.pool())
        .await
        .map_err(|e| AuthError::Internal(e.to_string()))?;
        Ok(rows
            .into_iter()
            .map(|r| {
                serde_json::json!({
                    "id": r.get::<Uuid,_>("id"),
                    "client_id": r.get::<String,_>("client_id"),
                    "name": r.get::<String,_>("name"),
                    "grant_types": r.get::<Vec<String>,_>("grant_types"),
                    "scopes": r.get::<Vec<String>,_>("scopes"),
                    "created_at": r.get::<DateTime<Utc>,_>("created_at"),
                })
            })
            .collect())
    }

    pub async fn delete_client(&self, id: Uuid) -> Result<(), AuthError> {
        sqlx::query("DELETE FROM oauth_clients WHERE id = $1")
            .bind(id)
            .execute(self.pool())
            .await
            .map_err(|e| AuthError::Internal(e.to_string()))?;
        Ok(())
    }

    // --- Roles / permissions CRUD ---
    pub async fn create_role(
        &self,
        account_id: Uuid,
        name: &str,
        description: Option<&str>,
    ) -> Result<Role, AuthError> {
        let id = Uuid::new_v4();
        let now = Utc::now();
        sqlx::query(
            "INSERT INTO roles (id, account_id, scope, name, description, created_at) VALUES ($1,$2,'account',$3,$4,$5)",
        )
        .bind(id)
        .bind(account_id)
        .bind(name)
        .bind(description)
        .bind(now)
        .execute(self.pool())
        .await
        .map_err(|e| AuthError::Internal(e.to_string()))?;
        Ok(Role {
            id,
            account_id,
            website_id: None,
            scope: authsvc_core::RoleScope::Account,
            name: name.to_string(),
            description: description.map(str::to_string),
            created_at: now,
        })
    }

    pub async fn create_permission(
        &self,
        _account_id: Uuid,
        resource: &str,
        action: &str,
    ) -> Result<Permission, AuthError> {
        let id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO permissions (id, resource, action) VALUES ($1,$2,$3)",
        )
        .bind(id)
        .bind(resource)
        .bind(action)
        .execute(self.pool())
        .await
        .map_err(|e| AuthError::Internal(e.to_string()))?;
        Ok(Permission {
            id,
            resource: resource.to_string(),
            action: action.to_string(),
            description: None,
        })
    }

    pub async fn add_role_inheritance(
        &self,
        child_role_id: Uuid,
        parent_role_id: Uuid,
    ) -> Result<(), AuthError> {
        sqlx::query(
            "INSERT INTO role_hierarchy (child_role_id, parent_role_id) VALUES ($1, $2)
             ON CONFLICT DO NOTHING",
        )
        .bind(child_role_id)
        .bind(parent_role_id)
        .execute(self.pool())
        .await
        .map_err(|e| AuthError::Internal(e.to_string()))?;
        Ok(())
    }

    pub async fn remove_role_inheritance(
        &self,
        child_role_id: Uuid,
        parent_role_id: Uuid,
    ) -> Result<(), AuthError> {
        sqlx::query(
            "DELETE FROM role_hierarchy WHERE child_role_id = $1 AND parent_role_id = $2",
        )
        .bind(child_role_id)
        .bind(parent_role_id)
        .execute(self.pool())
        .await
        .map_err(|e| AuthError::Internal(e.to_string()))?;
        Ok(())
    }

    pub async fn attach_permission_to_role(
        &self,
        role_id: Uuid,
        permission_id: Uuid,
    ) -> Result<(), AuthError> {
        sqlx::query(
            "INSERT INTO role_permissions (role_id, permission_id) VALUES ($1, $2)
             ON CONFLICT DO NOTHING",
        )
        .bind(role_id)
        .bind(permission_id)
        .execute(self.pool())
        .await
        .map_err(|e| AuthError::Internal(e.to_string()))?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn create_casbin_rule(
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
        let row = sqlx::query(
            "INSERT INTO casbin_rules (account_id, ptype, v0, v1, v2, v3, v4, v5)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING id",
        )
        .bind(account_id)
        .bind(ptype)
        .bind(v0)
        .bind(v1)
        .bind(v2)
        .bind(v3)
        .bind(v4)
        .bind(v5)
        .fetch_one(self.pool())
        .await
        .map_err(|e| AuthError::Internal(e.to_string()))?;
        Ok(row.get("id"))
    }

    pub async fn delete_casbin_rule(&self, id: i32) -> Result<(), AuthError> {
        sqlx::query("DELETE FROM casbin_rules WHERE id = $1")
            .bind(id)
            .execute(self.pool())
            .await
            .map_err(|e| AuthError::Internal(e.to_string()))?;
        Ok(())
    }

    pub async fn list_casbin_rules(
        &self,
        account_id: Uuid,
    ) -> Result<Vec<(i32, String, Option<String>, Option<String>, Option<String>, Option<String>, Option<String>, Option<String>)>, AuthError>
    {
        let rows = sqlx::query(
            "SELECT id, ptype, v0, v1, v2, v3, v4, v5 FROM casbin_rules WHERE account_id = $1 ORDER BY id",
        )
        .bind(account_id)
        .fetch_all(self.pool())
        .await
        .map_err(|e| AuthError::Internal(e.to_string()))?;

        Ok(rows
            .into_iter()
            .map(|r| {
                (
                    r.get("id"),
                    r.get("ptype"),
                    r.get("v0"),
                    r.get("v1"),
                    r.get("v2"),
                    r.get("v3"),
                    r.get("v4"),
                    r.get("v5"),
                )
            })
            .collect())
    }

    // --- OIDC authorization codes ---
    #[allow(clippy::too_many_arguments)]
    pub async fn store_auth_code(
        &self,
        code: &str,
        client_id: Uuid,
        user_id: Uuid,
        redirect_uri: &str,
        code_challenge: &str,
        scopes: &[String],
        expires_at: DateTime<Utc>,
    ) -> Result<(), AuthError> {
        sqlx::query(
            "INSERT INTO authorization_codes (code, client_id, user_id, redirect_uri, code_challenge, scopes, expires_at)
             VALUES ($1,$2,$3,$4,$5,$6,$7)",
        )
        .bind(code)
        .bind(client_id)
        .bind(user_id)
        .bind(redirect_uri)
        .bind(code_challenge)
        .bind(scopes)
        .bind(expires_at)
        .execute(self.pool())
        .await
        .map_err(|e| AuthError::Internal(e.to_string()))?;
        Ok(())
    }

    pub async fn consume_auth_code(
        &self,
        code: &str,
        redirect_uri: &str,
        code_verifier: &str,
    ) -> Result<Option<(Uuid, Uuid, Vec<String>)>, AuthError> {
        use sha2::{Digest, Sha256};
        let row = sqlx::query(
            "SELECT client_id, user_id, redirect_uri, code_challenge, scopes, expires_at, used
             FROM authorization_codes WHERE code = $1",
        )
        .bind(code)
        .fetch_optional(self.pool())
        .await
        .map_err(|e| AuthError::Internal(e.to_string()))?;

        let Some(r) = row else {
            return Ok(None);
        };
        if r.get::<bool, _>("used") {
            return Err(AuthError::InvalidToken);
        }
        let expires: DateTime<Utc> = r.get("expires_at");
        if expires < Utc::now() {
            return Ok(None);
        }
        if r.get::<String, _>("redirect_uri") != redirect_uri {
            return Err(AuthError::Validation("redirect_uri mismatch".into()));
        }
        let challenge: String = r.get("code_challenge");
        let verifier_hash = base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            Sha256::digest(code_verifier.as_bytes()),
        );
        if challenge != verifier_hash {
            return Err(AuthError::InvalidCredentials);
        }
        sqlx::query("UPDATE authorization_codes SET used = TRUE WHERE code = $1")
            .bind(code)
            .execute(self.pool())
            .await
            .map_err(|e| AuthError::Internal(e.to_string()))?;
        Ok(Some((
            r.get("user_id"),
            r.get("client_id"),
            r.get("scopes"),
        )))
    }

    pub async fn store_login_state(
        &self,
        state: &str,
        client_id: &str,
        redirect_uri: &str,
        code_challenge: &str,
        scopes: &[String],
        expires_at: DateTime<Utc>,
    ) -> Result<(), AuthError> {
        sqlx::query(
            "INSERT INTO login_states (state, client_id, redirect_uri, code_challenge, scopes, expires_at)
             VALUES ($1,$2,$3,$4,$5,$6)",
        )
        .bind(state)
        .bind(client_id)
        .bind(redirect_uri)
        .bind(code_challenge)
        .bind(scopes)
        .bind(expires_at)
        .execute(self.pool())
        .await
        .map_err(|e| AuthError::Internal(e.to_string()))?;
        Ok(())
    }

    pub async fn get_login_state(&self, state: &str) -> Result<Option<(String, String, String, Vec<String>)>, AuthError> {
        let row = sqlx::query(
            "SELECT client_id, redirect_uri, code_challenge, scopes, expires_at FROM login_states WHERE state = $1",
        )
        .bind(state)
        .fetch_optional(self.pool())
        .await
        .map_err(|e| AuthError::Internal(e.to_string()))?;
        let Some(r) = row else {
            return Ok(None);
        };
        let expires: DateTime<Utc> = r.get("expires_at");
        if expires < Utc::now() {
            return Ok(None);
        }
        Ok(Some((
            r.get("client_id"),
            r.get("redirect_uri"),
            r.get("code_challenge"),
            r.get("scopes"),
        )))
    }

    // --- MFA ---
    pub async fn store_mfa_secret(&self, user_id: Uuid, encrypted: &str, recovery_hashes: &[String]) -> Result<(), AuthError> {
        sqlx::query(
            "INSERT INTO user_mfa_secrets (user_id, encrypted_secret, recovery_codes_hash)
             VALUES ($1,$2,$3) ON CONFLICT (user_id) DO UPDATE SET encrypted_secret = $2, recovery_codes_hash = $3",
        )
        .bind(user_id)
        .bind(encrypted)
        .bind(recovery_hashes)
        .execute(self.pool())
        .await
        .map_err(|e| AuthError::Internal(e.to_string()))?;
        sqlx::query("UPDATE users SET mfa_enabled = TRUE WHERE id = $1")
            .bind(user_id)
            .execute(self.pool())
            .await
            .map_err(|e| AuthError::Internal(e.to_string()))?;
        Ok(())
    }

    pub async fn get_mfa_secret(&self, user_id: Uuid) -> Result<Option<String>, AuthError> {
        let row = sqlx::query("SELECT encrypted_secret FROM user_mfa_secrets WHERE user_id = $1")
            .bind(user_id)
            .fetch_optional(self.pool())
            .await
            .map_err(|e| AuthError::Internal(e.to_string()))?;
        Ok(row.map(|r| r.get("encrypted_secret")))
    }

    pub async fn store_mfa_challenge(&self, id: Uuid, user_id: Uuid, client_id: Uuid, expires: DateTime<Utc>) -> Result<(), AuthError> {
        sqlx::query(
            "INSERT INTO mfa_challenges (challenge_id, user_id, client_id, expires_at) VALUES ($1,$2,$3,$4)",
        )
        .bind(id)
        .bind(user_id)
        .bind(client_id)
        .bind(expires)
        .execute(self.pool())
        .await
        .map_err(|e| AuthError::Internal(e.to_string()))?;
        Ok(())
    }

    pub async fn complete_mfa_challenge(&self, id: Uuid) -> Result<Option<(Uuid, Uuid)>, AuthError> {
        let row = sqlx::query(
            "SELECT user_id, client_id, expires_at, completed FROM mfa_challenges WHERE challenge_id = $1",
        )
        .bind(id)
        .fetch_optional(self.pool())
        .await
        .map_err(|e| AuthError::Internal(e.to_string()))?;
        let Some(r) = row else {
            return Ok(None);
        };
        if r.get::<bool, _>("completed") || r.get::<DateTime<Utc>, _>("expires_at") < Utc::now() {
            return Ok(None);
        }
        sqlx::query("UPDATE mfa_challenges SET completed = TRUE WHERE challenge_id = $1")
            .bind(id)
            .execute(self.pool())
            .await
            .map_err(|e| AuthError::Internal(e.to_string()))?;
        Ok(Some((r.get("user_id"), r.get("client_id"))))
    }

    // --- Magic links ---
    pub async fn store_magic_link(&self, hash: &str, email: &str, expires: DateTime<Utc>) -> Result<(), AuthError> {
        sqlx::query(
            "INSERT INTO magic_link_tokens (token_hash, email, expires_at) VALUES ($1,$2,$3)",
        )
        .bind(hash)
        .bind(email)
        .bind(expires)
        .execute(self.pool())
        .await
        .map_err(|e| AuthError::Internal(e.to_string()))?;
        Ok(())
    }

    pub async fn consume_magic_link(&self, hash: &str) -> Result<Option<String>, AuthError> {
        let row = sqlx::query(
            "SELECT email, expires_at, used FROM magic_link_tokens WHERE token_hash = $1",
        )
        .bind(hash)
        .fetch_optional(self.pool())
        .await
        .map_err(|e| AuthError::Internal(e.to_string()))?;
        let Some(r) = row else {
            return Ok(None);
        };
        if r.get::<bool, _>("used") || r.get::<DateTime<Utc>, _>("expires_at") < Utc::now() {
            return Ok(None);
        }
        sqlx::query("UPDATE magic_link_tokens SET used = TRUE WHERE token_hash = $1")
            .bind(hash)
            .execute(self.pool())
            .await
            .map_err(|e| AuthError::Internal(e.to_string()))?;
        Ok(Some(r.get("email")))
    }

    // --- Federation ---
    pub async fn link_identity(
        &self,
        user_id: Uuid,
        provider: &str,
        subject: &str,
        email: Option<&str>,
    ) -> Result<(), AuthError> {
        sqlx::query(
            "INSERT INTO user_identities (id, user_id, provider, provider_subject, email)
             VALUES ($1,$2,$3,$4,$5) ON CONFLICT (provider, provider_subject) DO NOTHING",
        )
        .bind(Uuid::new_v4())
        .bind(user_id)
        .bind(provider)
        .bind(subject)
        .bind(email)
        .execute(self.pool())
        .await
        .map_err(|e| AuthError::Internal(e.to_string()))?;
        Ok(())
    }

    pub async fn find_identity(&self, provider: &str, subject: &str) -> Result<Option<Uuid>, AuthError> {
        let row = sqlx::query("SELECT user_id FROM user_identities WHERE provider = $1 AND provider_subject = $2")
            .bind(provider)
            .bind(subject)
            .fetch_optional(self.pool())
            .await
            .map_err(|e| AuthError::Internal(e.to_string()))?;
        Ok(row.map(|r| r.get("user_id")))
    }

    pub async fn store_federation_state(&self, state: &str, account_id: Uuid, provider: &str, expires: DateTime<Utc>) -> Result<(), AuthError> {
        sqlx::query(
            "INSERT INTO federation_states (state, account_id, provider, expires_at) VALUES ($1,$2,$3,$4)",
        )
        .bind(state)
        .bind(account_id)
        .bind(provider)
        .bind(expires)
        .execute(self.pool())
        .await
        .map_err(|e| AuthError::Internal(e.to_string()))?;
        Ok(())
    }

    pub async fn consume_federation_state(&self, state: &str) -> Result<Option<(Uuid, String)>, AuthError> {
        let row = sqlx::query("SELECT account_id, provider, expires_at FROM federation_states WHERE state = $1")
            .bind(state)
            .fetch_optional(self.pool())
            .await
            .map_err(|e| AuthError::Internal(e.to_string()))?;
        let Some(r) = row else {
            return Ok(None);
        };
        if r.get::<DateTime<Utc>, _>("expires_at") < Utc::now() {
            return Ok(None);
        }
        sqlx::query("DELETE FROM federation_states WHERE state = $1")
            .bind(state)
            .execute(self.pool())
            .await
            .map_err(|e| AuthError::Internal(e.to_string()))?;
        Ok(Some((r.get("account_id"), r.get("provider"))))
    }

    // --- API keys ---
    pub async fn create_api_key(
        &self,
        account_id: Uuid,
        name: &str,
        prefix: &str,
        hash: &str,
        scopes: &[String],
        expires_at: Option<DateTime<Utc>>,
    ) -> Result<Uuid, AuthError> {
        let id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO api_keys (id, account_id, name, key_prefix, key_hash, scopes, expires_at) VALUES ($1,$2,$3,$4,$5,$6,$7)",
        )
        .bind(id)
        .bind(account_id)
        .bind(name)
        .bind(prefix)
        .bind(hash)
        .bind(scopes)
        .bind(expires_at)
        .execute(self.pool())
        .await
        .map_err(|e| AuthError::Internal(e.to_string()))?;
        Ok(id)
    }

    pub async fn find_api_key(&self, hash: &str) -> Result<Option<(Uuid, Uuid, Vec<String>)>, AuthError> {
        let row = sqlx::query(
            "SELECT id, account_id, scopes, expires_at, revoked FROM api_keys WHERE key_hash = $1",
        )
        .bind(hash)
        .fetch_optional(self.pool())
        .await
        .map_err(|e| AuthError::Internal(e.to_string()))?;
        let Some(r) = row else {
            return Ok(None);
        };
        if r.get::<bool, _>("revoked") {
            return Ok(None);
        }
        if let Some(exp) = r.get::<Option<DateTime<Utc>>, _>("expires_at") {
            if exp < Utc::now() {
                return Ok(None);
            }
        }
        Ok(Some((r.get("id"), r.get("account_id"), r.get("scopes"))))
    }

    pub async fn revoke_api_key(&self, id: Uuid) -> Result<(), AuthError> {
        sqlx::query("UPDATE api_keys SET revoked = TRUE WHERE id = $1")
            .bind(id)
            .execute(self.pool())
            .await
            .map_err(|e| AuthError::Internal(e.to_string()))?;
        Ok(())
    }

    // --- Audit + webhooks ---
    pub async fn audit(
        &self,
        account_id: Option<Uuid>,
        actor: Option<&str>,
        action: &str,
        resource: Option<&str>,
        ip: Option<&str>,
        metadata: serde_json::Value,
    ) -> Result<(), AuthError> {
        sqlx::query(
            "INSERT INTO audit_events (id, account_id, actor_id, action, resource, ip_address, metadata) VALUES ($1,$2,$3,$4,$5,$6,$7)",
        )
        .bind(Uuid::new_v4())
        .bind(account_id)
        .bind(actor)
        .bind(action)
        .bind(resource)
        .bind(ip)
        .bind(metadata)
        .execute(self.pool())
        .await
        .map_err(|e| AuthError::Internal(e.to_string()))?;
        Ok(())
    }

    pub async fn create_webhook(&self, account_id: Uuid, url: &str, secret: &str, events: &[String]) -> Result<Uuid, AuthError> {
        let id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO webhooks (id, account_id, url, secret, events) VALUES ($1,$2,$3,$4,$5)",
        )
        .bind(id)
        .bind(account_id)
        .bind(url)
        .bind(secret)
        .bind(events)
        .execute(self.pool())
        .await
        .map_err(|e| AuthError::Internal(e.to_string()))?;
        Ok(id)
    }

    pub async fn list_webhooks_for_event(&self, account_id: Uuid, event: &str) -> Result<Vec<(Uuid, String, String)>, AuthError> {
        let rows = sqlx::query(
            "SELECT id, url, secret FROM webhooks WHERE account_id = $1 AND enabled = TRUE AND $2 = ANY(events)",
        )
        .bind(account_id)
        .bind(event)
        .fetch_all(self.pool())
        .await
        .map_err(|e| AuthError::Internal(e.to_string()))?;
        Ok(rows
            .into_iter()
            .map(|r| (r.get("id"), r.get("url"), r.get("secret")))
            .collect())
    }

    pub async fn record_webhook_delivery(
        &self,
        id: Uuid,
        webhook_id: Uuid,
        event: &str,
        status: &str,
        attempts: i32,
        last_error: Option<&str>,
    ) -> Result<(), AuthError> {
        sqlx::query(
            "INSERT INTO webhook_deliveries (id, webhook_id, event, status, attempts, last_error)
             VALUES ($1,$2,$3,$4,$5,$6)
             ON CONFLICT (id) DO UPDATE SET status = $4, attempts = $5, last_error = $6, updated_at = NOW()",
        )
        .bind(id)
        .bind(webhook_id)
        .bind(event)
        .bind(status)
        .bind(attempts)
        .bind(last_error)
        .execute(self.pool())
        .await
        .map_err(|e| AuthError::Internal(e.to_string()))?;
        Ok(())
    }

    // --- Signing keys ---
    pub async fn store_signing_key(&self, kid: &str, private_pem: &str, public_pem: &str) -> Result<(), AuthError> {
        sqlx::query(
            "INSERT INTO signing_keys (kid, private_key_pem, public_key_pem, active) VALUES ($1,$2,$3,TRUE)
             ON CONFLICT (kid) DO UPDATE SET private_key_pem = $2, public_key_pem = $3, active = TRUE",
        )
        .bind(kid)
        .bind(private_pem)
        .bind(public_pem)
        .execute(self.pool())
        .await
        .map_err(|e| AuthError::Internal(e.to_string()))?;
        Ok(())
    }

    pub async fn get_active_signing_key(
        &self,
    ) -> Result<Option<(String, String, String)>, AuthError> {
        let row = sqlx::query(
            "SELECT kid, private_key_pem, public_key_pem FROM signing_keys
             WHERE active = TRUE ORDER BY created_at DESC LIMIT 1",
        )
        .fetch_optional(self.pool())
        .await
        .map_err(|e| AuthError::Internal(e.to_string()))?;
        Ok(row.map(|r| {
            (
                r.get("kid"),
                r.get("private_key_pem"),
                r.get("public_key_pem"),
            )
        }))
    }

    pub async fn list_signing_keys_for_jwks(
        &self,
        grace_secs: u64,
    ) -> Result<Vec<(String, String)>, AuthError> {
        let rows = sqlx::query(
            "SELECT kid, public_key_pem FROM signing_keys
             WHERE active = TRUE
                OR (rotated_at IS NOT NULL AND rotated_at > NOW() - make_interval(secs => $1::double precision))",
        )
        .bind(grace_secs as f64)
        .fetch_all(self.pool())
        .await
        .map_err(|e| AuthError::Internal(e.to_string()))?;
        Ok(rows
            .into_iter()
            .map(|r| (r.get("kid"), r.get("public_key_pem")))
            .collect())
    }

    pub async fn deactivate_signing_keys(&self) -> Result<(), AuthError> {
        sqlx::query("UPDATE signing_keys SET active = FALSE, rotated_at = NOW() WHERE active = TRUE")
            .execute(self.pool())
            .await
            .map_err(|e| AuthError::Internal(e.to_string()))?;
        Ok(())
    }

    // --- WebAuthn ---
    pub async fn store_webauthn_credential(
        &self,
        user_id: Uuid,
        credential_id: &[u8],
        public_key: &[u8],
        name: Option<&str>,
    ) -> Result<Uuid, AuthError> {
        let id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO webauthn_credentials (id, user_id, credential_id, public_key, sign_count, name)
             VALUES ($1,$2,$3,$4,0,$5)",
        )
        .bind(id)
        .bind(user_id)
        .bind(credential_id)
        .bind(public_key)
        .bind(name)
        .execute(self.pool())
        .await
        .map_err(|e| AuthError::Internal(e.to_string()))?;
        Ok(id)
    }

    pub async fn list_webauthn_credentials(&self, user_id: Uuid) -> Result<Vec<authsvc_core::WebAuthnCredential>, AuthError> {
        let rows = sqlx::query(
            "SELECT id, user_id, credential_id, public_key, sign_count, name FROM webauthn_credentials WHERE user_id = $1",
        )
        .bind(user_id)
        .fetch_all(self.pool())
        .await
        .map_err(|e| AuthError::Internal(e.to_string()))?;
        Ok(rows
            .into_iter()
            .map(|r| authsvc_core::WebAuthnCredential {
                id: r.get("id"),
                user_id: r.get("user_id"),
                credential_id: r.get("credential_id"),
                public_key: r.get("public_key"),
                sign_count: r.get("sign_count"),
                name: r.get("name"),
            })
            .collect())
    }

    pub async fn update_webauthn_sign_count(&self, id: Uuid, sign_count: i64) -> Result<(), AuthError> {
        sqlx::query("UPDATE webauthn_credentials SET sign_count = $2 WHERE id = $1")
            .bind(id)
            .bind(sign_count)
            .execute(self.pool())
            .await
            .map_err(|e| AuthError::Internal(e.to_string()))?;
        Ok(())
    }

    // --- Portal / login selection ---
    pub async fn find_portal_by_domain(&self, domain: &str) -> Result<Option<PortalInfo>, AuthError> {
        let row = sqlx::query(
            "SELECT w.id AS website_id, w.account_id, w.slug AS website_slug, w.name AS website_name,
                    w.domain, w.portal_name, w.logo_url, w.portal_type,
                    a.slug AS account_slug, a.name AS account_name
             FROM websites w
             JOIN accounts a ON a.id = w.account_id
             WHERE LOWER(w.domain) = LOWER($1)
             LIMIT 1",
        )
        .bind(domain)
        .fetch_optional(self.pool())
        .await
        .map_err(|e| AuthError::Internal(e.to_string()))?;

        Ok(row.map(|r| PortalInfo {
            account_id: r.get("account_id"),
            account_slug: r.get("account_slug"),
            account_name: r.get("account_name"),
            website_id: r.get("website_id"),
            website_slug: r.get("website_slug"),
            website_name: r.get("website_name"),
            domain: r.get("domain"),
            portal_name: r.get("portal_name"),
            logo_url: r.get("logo_url"),
            portal_type: r.get("portal_type"),
        }))
    }

    pub async fn list_user_account_options(
        &self,
        user_id: Uuid,
    ) -> Result<Vec<AccountOption>, AuthError> {
        let rows = sqlx::query(
            "SELECT a.id AS account_id, a.slug, a.name, am.status
             FROM account_members am
             JOIN accounts a ON a.id = am.account_id
             WHERE am.user_id = $1
             ORDER BY a.name",
        )
        .bind(user_id)
        .fetch_all(self.pool())
        .await
        .map_err(|e| AuthError::Internal(e.to_string()))?;

        Ok(rows
            .into_iter()
            .map(|r| AccountOption {
                account_id: r.get("account_id"),
                slug: r.get("slug"),
                name: r.get("name"),
                status: r.get("status"),
            })
            .collect())
    }

    // --- Email OTP ---
    pub async fn store_email_otp(
        &self,
        email: &str,
        code_hash: &str,
        expires_at: DateTime<Utc>,
    ) -> Result<(), AuthError> {
        sqlx::query(
            "INSERT INTO email_otp_codes (id, email, code_hash, expires_at) VALUES ($1, $2, $3, $4)",
        )
        .bind(Uuid::new_v4())
        .bind(email)
        .bind(code_hash)
        .bind(expires_at)
        .execute(self.pool())
        .await
        .map_err(|e| AuthError::Internal(e.to_string()))?;
        Ok(())
    }

    pub async fn consume_email_otp(&self, email: &str, code_hash: &str) -> Result<bool, AuthError> {
        let row = sqlx::query(
            "SELECT id, expires_at, used FROM email_otp_codes
             WHERE LOWER(email) = LOWER($1) AND code_hash = $2
             ORDER BY created_at DESC LIMIT 1",
        )
        .bind(email)
        .bind(code_hash)
        .fetch_optional(self.pool())
        .await
        .map_err(|e| AuthError::Internal(e.to_string()))?;

        let Some(r) = row else {
            return Ok(false);
        };
        if r.get::<bool, _>("used") || r.get::<DateTime<Utc>, _>("expires_at") < Utc::now() {
            return Ok(false);
        }
        sqlx::query("UPDATE email_otp_codes SET used = TRUE WHERE id = $1")
            .bind(r.get::<Uuid, _>("id"))
            .execute(self.pool())
            .await
            .map_err(|e| AuthError::Internal(e.to_string()))?;
        Ok(true)
    }

    // --- Phone OTP ---
    pub async fn store_phone_otp(
        &self,
        phone: &str,
        code_hash: &str,
        expires_at: DateTime<Utc>,
    ) -> Result<(), AuthError> {
        sqlx::query(
            "INSERT INTO phone_otp_codes (id, phone, code_hash, expires_at) VALUES ($1, $2, $3, $4)",
        )
        .bind(Uuid::new_v4())
        .bind(phone)
        .bind(code_hash)
        .bind(expires_at)
        .execute(self.pool())
        .await
        .map_err(|e| AuthError::Internal(e.to_string()))?;
        Ok(())
    }

    pub async fn consume_phone_otp(&self, phone: &str, code_hash: &str) -> Result<bool, AuthError> {
        let row = sqlx::query(
            "SELECT id, expires_at, used FROM phone_otp_codes
             WHERE phone = $1 AND code_hash = $2
             ORDER BY created_at DESC LIMIT 1",
        )
        .bind(phone)
        .bind(code_hash)
        .fetch_optional(self.pool())
        .await
        .map_err(|e| AuthError::Internal(e.to_string()))?;

        let Some(r) = row else {
            return Ok(false);
        };
        if r.get::<bool, _>("used") || r.get::<DateTime<Utc>, _>("expires_at") < Utc::now() {
            return Ok(false);
        }
        sqlx::query("UPDATE phone_otp_codes SET used = TRUE WHERE id = $1")
            .bind(r.get::<Uuid, _>("id"))
            .execute(self.pool())
            .await
            .map_err(|e| AuthError::Internal(e.to_string()))?;
        Ok(true)
    }

    pub async fn find_user_id_by_phone(&self, phone: &str) -> Result<Option<Uuid>, AuthError> {
        let row = sqlx::query(
            "SELECT user_id FROM user_phones WHERE phone = $1 AND verified = TRUE",
        )
        .bind(phone)
        .fetch_optional(self.pool())
        .await
        .map_err(|e| AuthError::Internal(e.to_string()))?;
        Ok(row.map(|r| r.get("user_id")))
    }

    pub async fn link_verified_phone(&self, user_id: Uuid, phone: &str) -> Result<(), AuthError> {
        sqlx::query(
            "INSERT INTO user_phones (user_id, phone, verified) VALUES ($1, $2, TRUE)
             ON CONFLICT (phone) DO UPDATE SET user_id = $1, verified = TRUE",
        )
        .bind(user_id)
        .bind(phone)
        .execute(self.pool())
        .await
        .map_err(|e| AuthError::Internal(e.to_string()))?;
        Ok(())
    }
}
