use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountMember {
    pub account_id: Uuid,
    pub user_id: Uuid,
    pub role_id: Option<Uuid>,
    pub display_name: Option<String>,
    pub status: String,
    pub joined_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebsiteMember {
    pub website_id: Uuid,
    pub user_id: Uuid,
    pub role_id: Option<Uuid>,
    pub status: String,
    pub joined_at: DateTime<Utc>,
}
