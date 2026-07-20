use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub id: Uuid,
    pub user_id: Uuid,
    pub account_id: Option<Uuid>,
    pub website_id: Option<Uuid>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}
