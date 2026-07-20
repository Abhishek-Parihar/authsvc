use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RoleScope {
    Account,
    Website,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Role {
    pub id: Uuid,
    pub account_id: Uuid,
    pub website_id: Option<Uuid>,
    pub scope: RoleScope,
    pub name: String,
    pub description: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Permission {
    pub id: Uuid,
    pub resource: String,
    pub action: String,
    pub description: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthzCheck {
    pub subject_id: Uuid,
    pub account_id: Uuid,
    pub website_id: Option<Uuid>,
    pub action: String,
    pub resource: String,
    pub context: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthzResult {
    pub allowed: bool,
    pub reason: Option<String>,
}
