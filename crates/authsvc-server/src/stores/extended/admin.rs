use authsvc_core::{AuthError, Permission, Role};
use chrono::{DateTime, Utc};
use sqlx::Row;
use uuid::Uuid;

use super::super::PostgresStore;

impl PostgresStore {
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

}
