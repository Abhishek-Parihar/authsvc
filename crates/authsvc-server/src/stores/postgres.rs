use async_trait::async_trait;
use authsvc_core::{
    client::{CreateOAuthClient, OAuthClient},
    role::{Permission, Role},
    tenant::Tenant,
    user::{CreateUser, User},
    AuthError, ClientRepository, RefreshTokenRecord, RefreshTokenRepository,
    RoleRepository, TenantRepository, UserRepository,
};
use chrono::{DateTime, Utc};
use sqlx::{PgPool, Row};
use uuid::Uuid;

#[derive(Clone)]
pub struct PostgresStore {
    pool: PgPool,
}

impl PostgresStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    pub async fn migrate(&self) -> Result<(), AuthError> {
        sqlx::migrate!("../../migrations")
            .run(&self.pool)
            .await
            .map_err(|e| AuthError::Internal(e.to_string()))
    }
}

#[async_trait]
impl TenantRepository for PostgresStore {
    async fn find_by_slug(&self, slug: &str) -> Result<Option<Tenant>, AuthError> {
        let row = sqlx::query(
            "SELECT id, slug, name, created_at FROM tenants WHERE slug = $1",
        )
        .bind(slug)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| AuthError::Internal(e.to_string()))?;

        Ok(row.map(|r| Tenant {
            id: r.get("id"),
            slug: r.get("slug"),
            name: r.get("name"),
            created_at: r.get("created_at"),
        }))
    }

    async fn find_by_id(&self, id: Uuid) -> Result<Option<Tenant>, AuthError> {
        let row = sqlx::query(
            "SELECT id, slug, name, created_at FROM tenants WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| AuthError::Internal(e.to_string()))?;

        Ok(row.map(|r| Tenant {
            id: r.get("id"),
            slug: r.get("slug"),
            name: r.get("name"),
            created_at: r.get("created_at"),
        }))
    }

    async fn ensure_default(&self) -> Result<Tenant, AuthError> {
        if let Some(t) = self.find_by_slug("default").await? {
            return Ok(t);
        }

        let id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO tenants (id, slug, name) VALUES ($1, $2, $3)",
        )
        .bind(id)
        .bind("default")
        .bind("Default Tenant")
        .execute(&self.pool)
        .await
        .map_err(|e| AuthError::Internal(e.to_string()))?;

        // seed admin role + permissions
        let role_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO roles (id, tenant_id, name, description) VALUES ($1, $2, $3, $4)",
        )
        .bind(role_id)
        .bind(id)
        .bind("admin")
        .bind("Administrator")
        .execute(&self.pool)
        .await
        .map_err(|e| AuthError::Internal(e.to_string()))?;

        for (resource, action) in [("*", "*"), ("users", "read"), ("users", "write")] {
            let perm_id = Uuid::new_v4();
            sqlx::query(
                "INSERT INTO permissions (id, tenant_id, resource, action) VALUES ($1, $2, $3, $4)
                 ON CONFLICT (tenant_id, resource, action) DO NOTHING",
            )
            .bind(perm_id)
            .bind(id)
            .bind(resource)
            .bind(action)
            .execute(&self.pool)
            .await
            .map_err(|e| AuthError::Internal(e.to_string()))?;

            sqlx::query(
                "INSERT INTO role_permissions (role_id, permission_id)
                 SELECT $1, p.id FROM permissions p
                 WHERE p.tenant_id = $2 AND p.resource = $3 AND p.action = $4
                 ON CONFLICT DO NOTHING",
            )
            .bind(role_id)
            .bind(id)
            .bind(resource)
            .bind(action)
            .execute(&self.pool)
            .await
            .map_err(|e| AuthError::Internal(e.to_string()))?;
        }

        TenantRepository::find_by_id(self, id)
            .await?
            .ok_or_else(|| AuthError::Internal("failed to create default tenant".into()))
    }
}

#[async_trait]
impl UserRepository for PostgresStore {
    async fn create(&self, user: &CreateUser, password_hash: &str) -> Result<User, AuthError> {
        let id = Uuid::new_v4();
        let now = Utc::now();

        let result = sqlx::query(
            "INSERT INTO users (id, tenant_id, email, password_hash, display_name, created_at, updated_at)
             VALUES ($1, $2, $3, $4, $5, $6, $6)",
        )
        .bind(id)
        .bind(user.tenant_id)
        .bind(&user.email)
        .bind(password_hash)
        .bind(&user.display_name)
        .bind(now)
        .execute(&self.pool)
        .await;

        match result {
            Ok(_) => Ok(User {
                id,
                tenant_id: user.tenant_id,
                email: user.email.clone(),
                password_hash: Some(password_hash.to_string()),
                display_name: user.display_name.clone(),
                email_verified: false,
                mfa_enabled: false,
                locked_until: None,
                created_at: now,
                updated_at: now,
            }),
            Err(sqlx::Error::Database(db)) if db.constraint().is_some() => {
                Err(AuthError::UserAlreadyExists)
            }
            Err(e) => Err(AuthError::Internal(e.to_string())),
        }
    }

    async fn find_by_email(&self, tenant_id: Uuid, email: &str) -> Result<Option<User>, AuthError> {
        let row = sqlx::query(
            "SELECT id, tenant_id, email, password_hash, display_name, email_verified,
                    mfa_enabled, locked_until, created_at, updated_at
             FROM users WHERE tenant_id = $1 AND email = $2",
        )
        .bind(tenant_id)
        .bind(email)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| AuthError::Internal(e.to_string()))?;

        Ok(row.map(map_user))
    }

    async fn find_by_id(&self, id: Uuid) -> Result<Option<User>, AuthError> {
        let row = sqlx::query(
            "SELECT id, tenant_id, email, password_hash, display_name, email_verified,
                    mfa_enabled, locked_until, created_at, updated_at
             FROM users WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| AuthError::Internal(e.to_string()))?;

        Ok(row.map(map_user))
    }
}

#[async_trait]
impl ClientRepository for PostgresStore {
    async fn create(
        &self,
        input: &CreateOAuthClient,
        client_id: &str,
        client_secret_hash: Option<&str>,
    ) -> Result<(OAuthClient, Option<String>), AuthError> {
        let id = Uuid::new_v4();
        let now = Utc::now();
        let plain_secret = if input.is_confidential {
            Some(crate::crypto::password::generate_refresh_token())
        } else {
            None
        };

        let secret_hash = if let Some(secret) = &plain_secret {
            Some(crate::crypto::password::hash_secret(secret)?)
        } else {
            client_secret_hash.map(str::to_string)
        };

        sqlx::query(
            "INSERT INTO oauth_clients
             (id, tenant_id, client_id, client_secret_hash, name, grant_types, redirect_uris, scopes, is_confidential, created_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
        )
        .bind(id)
        .bind(input.tenant_id)
        .bind(client_id)
        .bind(&secret_hash)
        .bind(&input.name)
        .bind(&input.grant_types)
        .bind(&input.redirect_uris)
        .bind(&input.scopes)
        .bind(input.is_confidential)
        .bind(now)
        .execute(&self.pool)
        .await
        .map_err(|e| AuthError::Internal(e.to_string()))?;

        Ok((
            OAuthClient {
                id,
                tenant_id: input.tenant_id,
                client_id: client_id.to_string(),
                client_secret_hash: secret_hash,
                name: input.name.clone(),
                grant_types: input.grant_types.clone(),
                redirect_uris: input.redirect_uris.clone(),
                scopes: input.scopes.clone(),
                is_confidential: input.is_confidential,
                created_at: now,
            },
            plain_secret,
        ))
    }

    async fn find_by_client_id(&self, client_id: &str) -> Result<Option<OAuthClient>, AuthError> {
        let row = sqlx::query(
            "SELECT id, tenant_id, client_id, client_secret_hash, name, grant_types,
                    redirect_uris, scopes, is_confidential, created_at
             FROM oauth_clients WHERE client_id = $1",
        )
        .bind(client_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| AuthError::Internal(e.to_string()))?;

        Ok(row.map(|r| OAuthClient {
            id: r.get("id"),
            tenant_id: r.get("tenant_id"),
            client_id: r.get("client_id"),
            client_secret_hash: r.get("client_secret_hash"),
            name: r.get("name"),
            grant_types: r.get("grant_types"),
            redirect_uris: r.get("redirect_uris"),
            scopes: r.get("scopes"),
            is_confidential: r.get("is_confidential"),
            created_at: r.get("created_at"),
        }))
    }
}

#[async_trait]
impl RoleRepository for PostgresStore {
    async fn list_user_permissions(
        &self,
        user_id: Uuid,
        tenant_id: Uuid,
    ) -> Result<Vec<Permission>, AuthError> {
        let rows = sqlx::query(
            "SELECT DISTINCT p.id, p.tenant_id, p.resource, p.action, p.description
             FROM permissions p
             JOIN role_permissions rp ON rp.permission_id = p.id
             JOIN user_roles ur ON ur.role_id = rp.role_id
             WHERE ur.user_id = $1 AND p.tenant_id = $2",
        )
        .bind(user_id)
        .bind(tenant_id)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| AuthError::Internal(e.to_string()))?;

        Ok(rows
            .into_iter()
            .map(|r| Permission {
                id: r.get("id"),
                tenant_id: r.get("tenant_id"),
                resource: r.get("resource"),
                action: r.get("action"),
                description: r.get("description"),
            })
            .collect())
    }

    async fn assign_role(&self, user_id: Uuid, role_id: Uuid) -> Result<(), AuthError> {
        sqlx::query(
            "INSERT INTO user_roles (user_id, role_id) VALUES ($1, $2) ON CONFLICT DO NOTHING",
        )
        .bind(user_id)
        .bind(role_id)
        .execute(&self.pool)
        .await
        .map_err(|e| AuthError::Internal(e.to_string()))?;
        Ok(())
    }

    async fn list_roles(&self, tenant_id: Uuid) -> Result<Vec<Role>, AuthError> {
        let rows = sqlx::query(
            "SELECT id, tenant_id, name, description, created_at FROM roles WHERE tenant_id = $1",
        )
        .bind(tenant_id)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| AuthError::Internal(e.to_string()))?;

        Ok(rows
            .into_iter()
            .map(|r| Role {
                id: r.get("id"),
                tenant_id: r.get("tenant_id"),
                name: r.get("name"),
                description: r.get("description"),
                created_at: r.get("created_at"),
            })
            .collect())
    }
}

#[async_trait]
impl RefreshTokenRepository for PostgresStore {
    async fn store(
        &self,
        token_hash: &str,
        user_id: Option<Uuid>,
        client_id: Uuid,
        tenant_id: Uuid,
        family_id: Uuid,
        expires_at: DateTime<Utc>,
    ) -> Result<(), AuthError> {
        sqlx::query(
            "INSERT INTO refresh_tokens (token_hash, user_id, client_id, tenant_id, family_id, expires_at)
             VALUES ($1, $2, $3, $4, $5, $6)",
        )
        .bind(token_hash)
        .bind(user_id)
        .bind(client_id)
        .bind(tenant_id)
        .bind(family_id)
        .bind(expires_at)
        .execute(&self.pool)
        .await
        .map_err(|e| AuthError::Internal(e.to_string()))?;
        Ok(())
    }

    async fn consume(&self, token_hash: &str) -> Result<Option<RefreshTokenRecord>, AuthError> {
        let row = sqlx::query(
            "SELECT user_id, client_id, tenant_id, family_id, revoked, expires_at
             FROM refresh_tokens WHERE token_hash = $1",
        )
        .bind(token_hash)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| AuthError::Internal(e.to_string()))?;

        let Some(r) = row else {
            return Ok(None);
        };

        let expires_at: DateTime<Utc> = r.get("expires_at");
        if expires_at < Utc::now() {
            return Ok(None);
        }

        let revoked: bool = r.get("revoked");
        if revoked {
            let family_id: Uuid = r.get("family_id");
            self.revoke_family(family_id).await?;
            return Err(AuthError::TokenReuse);
        }

        sqlx::query("UPDATE refresh_tokens SET revoked = TRUE WHERE token_hash = $1")
            .bind(token_hash)
            .execute(&self.pool)
            .await
            .map_err(|e| AuthError::Internal(e.to_string()))?;

        Ok(Some(RefreshTokenRecord {
            user_id: r.get("user_id"),
            client_id: r.get("client_id"),
            tenant_id: r.get("tenant_id"),
            family_id: r.get("family_id"),
            revoked: false,
        }))
    }

    async fn revoke_family(&self, family_id: Uuid) -> Result<(), AuthError> {
        sqlx::query("UPDATE refresh_tokens SET revoked = TRUE WHERE family_id = $1")
            .bind(family_id)
            .execute(&self.pool)
            .await
            .map_err(|e| AuthError::Internal(e.to_string()))?;
        Ok(())
    }
}

impl PostgresStore {
    pub async fn list_user_permissions(
        &self,
        user_id: Uuid,
        tenant_id: Uuid,
    ) -> Result<Vec<Permission>, AuthError> {
        RoleRepository::list_user_permissions(self, user_id, tenant_id).await
    }

    pub async fn assign_admin_role(&self, user_id: Uuid, tenant_id: Uuid) -> Result<(), AuthError> {
        let row = sqlx::query("SELECT id FROM roles WHERE tenant_id = $1 AND name = 'admin'")
            .bind(tenant_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| AuthError::Internal(e.to_string()))?;

        if let Some(r) = row {
            let role_id: Uuid = r.get("id");
            RoleRepository::assign_role(self, user_id, role_id).await?;
        }
        Ok(())
    }
}

fn map_user(r: sqlx::postgres::PgRow) -> User {
    User {
        id: r.get("id"),
        tenant_id: r.get("tenant_id"),
        email: r.get("email"),
        password_hash: r.get("password_hash"),
        display_name: r.get("display_name"),
        email_verified: r.get("email_verified"),
        mfa_enabled: r.get("mfa_enabled"),
        locked_until: r.get("locked_until"),
        created_at: r.get("created_at"),
        updated_at: r.get("updated_at"),
    }
}
