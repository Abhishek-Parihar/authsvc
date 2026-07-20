use async_trait::async_trait;
use authsvc_core::{
    account::{Account, CreateAccount},
    client::{CreateOAuthClient, OAuthClient},
    membership::{AccountMember, WebsiteMember},
    role::{Permission, Role, RoleScope},
    user::{CreateUser, User},
    website::{ClientType, CreateWebsite, Website},
    AccountRepository, AuthError, ClientRepository, MembershipRepository,
    RefreshTokenRecord, RefreshTokenRepository, RoleRepository, UserRepository,
    WebsiteRepository,
};
use chrono::{DateTime, Utc};
use sqlx::{PgPool, Row};
use uuid::Uuid;

#[derive(Clone)]
pub struct PostgresStore {
    pool: PgPool,
    read_pool: Option<PgPool>,
}

impl PostgresStore {
    pub fn new(pool: PgPool) -> Self {
        Self {
            pool,
            read_pool: None,
        }
    }

    pub fn with_read_pool(pool: PgPool, read_pool: PgPool) -> Self {
        Self {
            pool,
            read_pool: Some(read_pool),
        }
    }

    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    fn read_pool(&self) -> &PgPool {
        self.read_pool.as_ref().unwrap_or(&self.pool)
    }

    pub async fn migrate(&self) -> Result<(), AuthError> {
        sqlx::migrate!("../../migrations")
            .run(&self.pool)
            .await
            .map_err(|e| AuthError::Internal(e.to_string()))
    }

    pub async fn website_account_id(&self, website_id: Uuid) -> Result<Uuid, AuthError> {
        let row = sqlx::query("SELECT account_id FROM websites WHERE id = $1")
            .bind(website_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| AuthError::Internal(e.to_string()))?
            .ok_or_else(|| AuthError::NotFound("website".into()))?;
        Ok(row.get("account_id"))
    }
}

#[async_trait]
impl AccountRepository for PostgresStore {
    async fn find_by_slug(&self, slug: &str) -> Result<Option<Account>, AuthError> {
        let row = sqlx::query("SELECT id, slug, name, created_at FROM accounts WHERE slug = $1")
            .bind(slug)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| AuthError::Internal(e.to_string()))?;

        Ok(row.map(map_account))
    }

    async fn find_by_id(&self, id: Uuid) -> Result<Option<Account>, AuthError> {
        let row = sqlx::query("SELECT id, slug, name, created_at FROM accounts WHERE id = $1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| AuthError::Internal(e.to_string()))?;

        Ok(row.map(map_account))
    }

    async fn create(&self, input: &CreateAccount) -> Result<Account, AuthError> {
        let id = Uuid::new_v4();
        let now = Utc::now();
        sqlx::query("INSERT INTO accounts (id, slug, name, created_at) VALUES ($1, $2, $3, $4)")
            .bind(id)
            .bind(&input.slug)
            .bind(&input.name)
            .bind(now)
            .execute(&self.pool)
            .await
            .map_err(|e| AuthError::Internal(e.to_string()))?;
        Ok(Account {
            id,
            slug: input.slug.clone(),
            name: input.name.clone(),
            created_at: now,
        })
    }

    async fn ensure_default(&self) -> Result<Account, AuthError> {
        if let Some(a) = AccountRepository::find_by_slug(self, "default").await? {
            self.ensure_default_website(a.id).await?;
            return Ok(a);
        }

        let account = AccountRepository::create(
            self,
            &CreateAccount {
                slug: "default".into(),
                name: "Default Account".into(),
            },
        )
        .await?;

        self.create_website_internal(account.id, "default", "Default App", None)
            .await?;

        let role_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO roles (id, account_id, scope, name, description, created_at)
             VALUES ($1, $2, 'account', $3, $4, NOW())",
        )
        .bind(role_id)
        .bind(account.id)
        .bind("admin")
        .bind("Administrator")
        .execute(&self.pool)
        .await
        .map_err(|e| AuthError::Internal(e.to_string()))?;

        for (resource, action) in [("*", "*"), ("users", "read"), ("users", "write")] {
            let perm_id = Uuid::new_v4();
            sqlx::query(
                "INSERT INTO permissions (id, resource, action) VALUES ($1, $2, $3)
                 ON CONFLICT (resource, action) DO NOTHING",
            )
            .bind(perm_id)
            .bind(resource)
            .bind(action)
            .execute(&self.pool)
            .await
            .map_err(|e| AuthError::Internal(e.to_string()))?;

            sqlx::query(
                "INSERT INTO role_permissions (role_id, permission_id)
                 SELECT $1, p.id FROM permissions p
                 WHERE p.resource = $2 AND p.action = $3
                 ON CONFLICT DO NOTHING",
            )
            .bind(role_id)
            .bind(resource)
            .bind(action)
            .execute(&self.pool)
            .await
            .map_err(|e| AuthError::Internal(e.to_string()))?;
        }

        AccountRepository::find_by_id(self, account.id)
            .await?
            .ok_or_else(|| AuthError::Internal("failed to create default account".into()))
    }
}

impl PostgresStore {
    async fn ensure_default_website(&self, account_id: Uuid) -> Result<(), AuthError> {
        if WebsiteRepository::find_by_slug(self, account_id, "default")
            .await?
            .is_some()
        {
            return Ok(());
        }
        self.create_website_internal(account_id, "default", "Default App", None)
            .await?;
        Ok(())
    }

    async fn create_website_internal(
        &self,
        account_id: Uuid,
        slug: &str,
        name: &str,
        domain: Option<&str>,
    ) -> Result<Website, AuthError> {
        let id = Uuid::new_v4();
        let now = Utc::now();
        sqlx::query(
            "INSERT INTO websites (id, account_id, slug, name, domain, created_at)
             VALUES ($1, $2, $3, $4, $5, $6)",
        )
        .bind(id)
        .bind(account_id)
        .bind(slug)
        .bind(name)
        .bind(domain)
        .bind(now)
        .execute(&self.pool)
        .await
        .map_err(|e| AuthError::Internal(e.to_string()))?;
        Ok(Website {
            id,
            account_id,
            slug: slug.to_string(),
            name: name.to_string(),
            domain: domain.map(str::to_string),
            portal_name: None,
            logo_url: None,
            portal_type: "web".into(),
            created_at: now,
        })
    }
}

#[async_trait]
impl WebsiteRepository for PostgresStore {
    async fn find_by_slug(&self, account_id: Uuid, slug: &str) -> Result<Option<Website>, AuthError> {
        let row = sqlx::query(
            "SELECT id, account_id, slug, name, domain, portal_name, logo_url, portal_type, created_at
             FROM websites WHERE account_id = $1 AND slug = $2",
        )
        .bind(account_id)
        .bind(slug)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| AuthError::Internal(e.to_string()))?;

        Ok(row.map(map_website_row))
    }

    async fn find_by_id(&self, id: Uuid) -> Result<Option<Website>, AuthError> {
        let row = sqlx::query(
            "SELECT id, account_id, slug, name, domain, portal_name, logo_url, portal_type, created_at FROM websites WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| AuthError::Internal(e.to_string()))?;

        Ok(row.map(map_website_row))
    }

    async fn create(&self, input: &CreateWebsite) -> Result<Website, AuthError> {
        self.create_website_internal(
            input.account_id,
            &input.slug,
            &input.name,
            input.domain.as_deref(),
        )
        .await
    }

    async fn find_by_client_id(
        &self,
        client_id: &str,
    ) -> Result<Option<(Website, OAuthClient)>, AuthError> {
        let row = sqlx::query(
            "SELECT w.id, w.account_id, w.slug, w.name, w.domain, w.portal_name, w.logo_url, w.portal_type, w.created_at,
                    c.id as c_id, c.website_id, c.client_id, c.client_secret_hash, c.name as c_name,
                    c.client_type, c.grant_types, c.redirect_uris, c.scopes, c.is_confidential,
                    c.created_at as c_created_at
             FROM oauth_clients c
             JOIN websites w ON w.id = c.website_id
             WHERE c.client_id = $1",
        )
        .bind(client_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| AuthError::Internal(e.to_string()))?;

        Ok(row.map(|r| {
            let website = map_website(&r);
            let client_type: String = r.get("client_type");
            let client = OAuthClient {
                id: r.get("c_id"),
                website_id: r.get("website_id"),
                client_id: r.get("client_id"),
                client_secret_hash: r.get("client_secret_hash"),
                name: r.get("c_name"),
                client_type: ClientType::parse(&client_type).unwrap_or(ClientType::Web),
                grant_types: r.get("grant_types"),
                redirect_uris: r.get("redirect_uris"),
                scopes: r.get("scopes"),
                is_confidential: r.get("is_confidential"),
                created_at: r.get("c_created_at"),
            };
            (website, client)
        }))
    }
}

#[async_trait]
impl MembershipRepository for PostgresStore {
    async fn add_account_member(
        &self,
        account_id: Uuid,
        user_id: Uuid,
        role_id: Option<Uuid>,
    ) -> Result<AccountMember, AuthError> {
        let now = Utc::now();
        sqlx::query(
            "INSERT INTO account_members (account_id, user_id, role_id, status, joined_at)
             VALUES ($1, $2, $3, 'active', $4)
             ON CONFLICT (account_id, user_id) DO UPDATE SET role_id = EXCLUDED.role_id",
        )
        .bind(account_id)
        .bind(user_id)
        .bind(role_id)
        .bind(now)
        .execute(&self.pool)
        .await
        .map_err(|e| AuthError::Internal(e.to_string()))?;

        Ok(AccountMember {
            account_id,
            user_id,
            role_id,
            display_name: None,
            status: "active".into(),
            joined_at: now,
        })
    }

    async fn list_user_accounts(&self, user_id: Uuid) -> Result<Vec<AccountMember>, AuthError> {
        let rows = sqlx::query(
            "SELECT account_id, user_id, role_id, display_name, status, joined_at
             FROM account_members WHERE user_id = $1",
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| AuthError::Internal(e.to_string()))?;

        Ok(rows.into_iter().map(map_account_member).collect())
    }

    async fn get_account_member(
        &self,
        account_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<AccountMember>, AuthError> {
        let row = sqlx::query(
            "SELECT account_id, user_id, role_id, display_name, status, joined_at
             FROM account_members WHERE account_id = $1 AND user_id = $2",
        )
        .bind(account_id)
        .bind(user_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| AuthError::Internal(e.to_string()))?;

        Ok(row.map(map_account_member))
    }

    async fn add_website_member(
        &self,
        website_id: Uuid,
        user_id: Uuid,
        role_id: Option<Uuid>,
    ) -> Result<WebsiteMember, AuthError> {
        let now = Utc::now();
        sqlx::query(
            "INSERT INTO website_members (website_id, user_id, role_id, status, joined_at)
             VALUES ($1, $2, $3, 'active', $4)
             ON CONFLICT (website_id, user_id) DO UPDATE SET role_id = EXCLUDED.role_id",
        )
        .bind(website_id)
        .bind(user_id)
        .bind(role_id)
        .bind(now)
        .execute(&self.pool)
        .await
        .map_err(|e| AuthError::Internal(e.to_string()))?;

        Ok(WebsiteMember {
            website_id,
            user_id,
            role_id,
            status: "active".into(),
            joined_at: now,
        })
    }
}

#[async_trait]
impl UserRepository for PostgresStore {
    async fn create(&self, user: &CreateUser, password_hash: &str) -> Result<User, AuthError> {
        let id = Uuid::new_v4();
        let now = Utc::now();

        let result = sqlx::query(
            "INSERT INTO users (id, email, password_hash, display_name, status, created_at, updated_at)
             VALUES ($1, $2, $3, $4, 'active', $5, $5)",
        )
        .bind(id)
        .bind(&user.email)
        .bind(password_hash)
        .bind(&user.display_name)
        .bind(now)
        .execute(&self.pool)
        .await;

        match result {
            Ok(_) => Ok(User {
                id,
                email: user.email.clone(),
                password_hash: Some(password_hash.to_string()),
                display_name: user.display_name.clone(),
                email_verified: false,
                mfa_enabled: false,
                status: "active".into(),
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

    async fn find_by_email(&self, email: &str) -> Result<Option<User>, AuthError> {
        let row = sqlx::query(
            "SELECT id, email, password_hash, display_name, email_verified,
                    mfa_enabled, status, locked_until, created_at, updated_at
             FROM users WHERE LOWER(email) = LOWER($1) AND deleted_at IS NULL",
        )
        .bind(email)
        .fetch_optional(self.read_pool())
        .await
        .map_err(|e| AuthError::Internal(e.to_string()))?;

        Ok(row.map(map_user))
    }

    async fn find_by_id(&self, id: Uuid) -> Result<Option<User>, AuthError> {
        let row = sqlx::query(
            "SELECT id, email, password_hash, display_name, email_verified,
                    mfa_enabled, status, locked_until, created_at, updated_at
             FROM users WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| AuthError::Internal(e.to_string()))?;

        Ok(row.map(map_user))
    }

    async fn set_locked_until(&self, user_id: Uuid, until: DateTime<Utc>) -> Result<(), AuthError> {
        PostgresStore::set_locked_until(self, user_id, until).await
    }

    async fn count_users(&self) -> Result<i64, AuthError> {
        PostgresStore::count_users(self).await
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
             (id, website_id, client_id, client_secret_hash, name, client_type,
              grant_types, redirect_uris, scopes, is_confidential, created_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)",
        )
        .bind(id)
        .bind(input.website_id)
        .bind(client_id)
        .bind(&secret_hash)
        .bind(&input.name)
        .bind(input.client_type.as_str())
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
                website_id: input.website_id,
                client_id: client_id.to_string(),
                client_secret_hash: secret_hash,
                name: input.name.clone(),
                client_type: input.client_type,
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
            "SELECT id, website_id, client_id, client_secret_hash, name, client_type,
                    grant_types, redirect_uris, scopes, is_confidential, created_at
             FROM oauth_clients WHERE client_id = $1",
        )
        .bind(client_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| AuthError::Internal(e.to_string()))?;

        Ok(row.map(|r| {
            let client_type: String = r.get("client_type");
            OAuthClient {
                id: r.get("id"),
                website_id: r.get("website_id"),
                client_id: r.get("client_id"),
                client_secret_hash: r.get("client_secret_hash"),
                name: r.get("name"),
                client_type: ClientType::parse(&client_type).unwrap_or(ClientType::Web),
                grant_types: r.get("grant_types"),
                redirect_uris: r.get("redirect_uris"),
                scopes: r.get("scopes"),
                is_confidential: r.get("is_confidential"),
                created_at: r.get("created_at"),
            }
        }))
    }

    async fn find_client_id_by_uuid(&self, id: Uuid) -> Result<Option<String>, AuthError> {
        let row = sqlx::query_scalar("SELECT client_id FROM oauth_clients WHERE id = $1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| AuthError::Internal(e.to_string()))?;
        Ok(row)
    }
}

#[async_trait]
impl RoleRepository for PostgresStore {
    async fn list_user_permissions(
        &self,
        user_id: Uuid,
        account_id: Uuid,
        website_id: Option<Uuid>,
    ) -> Result<Vec<Permission>, AuthError> {
        let rows = sqlx::query(
            "WITH RECURSIVE effective_roles AS (
                SELECT role_id FROM account_members
                WHERE user_id = $1 AND account_id = $2 AND role_id IS NOT NULL
                UNION
                SELECT wm.role_id FROM website_members wm
                JOIN websites w ON w.id = wm.website_id
                WHERE wm.user_id = $1 AND w.account_id = $2
                  AND ($3::uuid IS NULL OR wm.website_id = $3)
                  AND wm.role_id IS NOT NULL
                UNION
                SELECT ur.role_id FROM user_roles ur
                JOIN roles r ON r.id = ur.role_id
                WHERE ur.user_id = $1 AND r.account_id = $2
                UNION
                SELECT rh.parent_role_id
                FROM role_hierarchy rh
                JOIN effective_roles er ON rh.child_role_id = er.role_id
            )
            SELECT DISTINCT p.id, p.resource, p.action, p.description
            FROM permissions p
            JOIN role_permissions rp ON rp.permission_id = p.id
            JOIN effective_roles er ON er.role_id = rp.role_id",
        )
        .bind(user_id)
        .bind(account_id)
        .bind(website_id)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| AuthError::Internal(e.to_string()))?;

        Ok(rows
            .into_iter()
            .map(|r| Permission {
                id: r.get("id"),
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

    async fn list_roles(&self, account_id: Uuid) -> Result<Vec<Role>, AuthError> {
        let rows = sqlx::query(
            "SELECT id, account_id, website_id, scope, name, description, created_at
             FROM roles WHERE account_id = $1",
        )
        .bind(account_id)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| AuthError::Internal(e.to_string()))?;

        Ok(rows.into_iter().map(map_role).collect())
    }
}

#[async_trait]
impl RefreshTokenRepository for PostgresStore {
    async fn store(
        &self,
        token_hash: &str,
        user_id: Option<Uuid>,
        client_id: Uuid,
        account_id: Uuid,
        family_id: Uuid,
        expires_at: DateTime<Utc>,
    ) -> Result<(), AuthError> {
        sqlx::query(
            "INSERT INTO refresh_tokens (token_hash, user_id, client_id, account_id, family_id, expires_at)
             VALUES ($1, $2, $3, $4, $5, $6)",
        )
        .bind(token_hash)
        .bind(user_id)
        .bind(client_id)
        .bind(account_id)
        .bind(family_id)
        .bind(expires_at)
        .execute(&self.pool)
        .await
        .map_err(|e| AuthError::Internal(e.to_string()))?;
        Ok(())
    }

    async fn consume(&self, token_hash: &str) -> Result<Option<RefreshTokenRecord>, AuthError> {
        let row = sqlx::query(
            "SELECT user_id, client_id, account_id, family_id, revoked, expires_at
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
            account_id: r.get("account_id"),
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
        account_id: Uuid,
        website_id: Option<Uuid>,
    ) -> Result<Vec<Permission>, AuthError> {
        RoleRepository::list_user_permissions(self, user_id, account_id, website_id).await
    }

    pub async fn assign_admin_membership(
        &self,
        user_id: Uuid,
        account_id: Uuid,
    ) -> Result<(), AuthError> {
        let row = sqlx::query("SELECT id FROM roles WHERE account_id = $1 AND name = 'admin'")
            .bind(account_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| AuthError::Internal(e.to_string()))?;

        if let Some(r) = row {
            let role_id: Uuid = r.get("id");
            MembershipRepository::add_account_member(self, account_id, user_id, Some(role_id))
                .await?;
        }
        Ok(())
    }

    pub async fn count_users(&self) -> Result<i64, AuthError> {
        let row: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM users")
            .fetch_one(&self.pool)
            .await
            .map_err(|e| AuthError::Internal(e.to_string()))?;
        Ok(row.0)
    }

    pub async fn set_locked_until(&self, user_id: Uuid, until: DateTime<Utc>) -> Result<(), AuthError> {
        sqlx::query("UPDATE users SET locked_until = $1, updated_at = NOW() WHERE id = $2")
            .bind(until)
            .bind(user_id)
            .execute(&self.pool)
            .await
            .map_err(|e| AuthError::Internal(e.to_string()))?;
        Ok(())
    }

    pub async fn clear_lock(&self, user_id: Uuid) -> Result<(), AuthError> {
        sqlx::query("UPDATE users SET locked_until = NULL, updated_at = NOW() WHERE id = $1")
            .bind(user_id)
            .execute(&self.pool)
            .await
            .map_err(|e| AuthError::Internal(e.to_string()))?;
        Ok(())
    }

    pub async fn ping(&self) -> Result<(), AuthError> {
        sqlx::query("SELECT 1")
            .execute(&self.pool)
            .await
            .map_err(|e| AuthError::Internal(e.to_string()))?;
        Ok(())
    }
}

fn map_account(r: sqlx::postgres::PgRow) -> Account {
    Account {
        id: r.get("id"),
        slug: r.get("slug"),
        name: r.get("name"),
        created_at: r.get("created_at"),
    }
}

fn map_website(r: &sqlx::postgres::PgRow) -> Website {
    Website {
        id: r.get("id"),
        account_id: r.get("account_id"),
        slug: r.get("slug"),
        name: r.get("name"),
        domain: r.get("domain"),
        portal_name: r.get("portal_name"),
        logo_url: r.get("logo_url"),
        portal_type: r.get("portal_type"),
        created_at: r.get("created_at"),
    }
}

fn map_website_row(r: sqlx::postgres::PgRow) -> Website {
    map_website(&r)
}

fn map_account_member(r: sqlx::postgres::PgRow) -> AccountMember {
    AccountMember {
        account_id: r.get("account_id"),
        user_id: r.get("user_id"),
        role_id: r.get("role_id"),
        display_name: r.get("display_name"),
        status: r.get("status"),
        joined_at: r.get("joined_at"),
    }
}

fn map_role(r: sqlx::postgres::PgRow) -> Role {
    let scope: String = r.get("scope");
    Role {
        id: r.get("id"),
        account_id: r.get("account_id"),
        website_id: r.get("website_id"),
        scope: if scope == "website" {
            RoleScope::Website
        } else {
            RoleScope::Account
        },
        name: r.get("name"),
        description: r.get("description"),
        created_at: r.get("created_at"),
    }
}

fn map_user(r: sqlx::postgres::PgRow) -> User {
    User {
        id: r.get("id"),
        email: r.get("email"),
        password_hash: r.get("password_hash"),
        display_name: r.get("display_name"),
        email_verified: r.get("email_verified"),
        mfa_enabled: r.get("mfa_enabled"),
        status: r.get("status"),
        locked_until: r.get("locked_until"),
        created_at: r.get("created_at"),
        updated_at: r.get("updated_at"),
    }
}
