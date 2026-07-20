use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Account {
    pub id: Uuid,
    pub slug: String,
    pub name: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateAccount {
    pub slug: String,
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountOption {
    pub account_id: Uuid,
    pub slug: String,
    pub name: String,
    pub status: String,
}
