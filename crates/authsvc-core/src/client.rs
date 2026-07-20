use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::website::ClientType;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthClient {
    pub id: Uuid,
    pub website_id: Uuid,
    pub client_id: String,
    pub client_secret_hash: Option<String>,
    pub name: String,
    pub client_type: ClientType,
    pub grant_types: Vec<String>,
    pub redirect_uris: Vec<String>,
    pub scopes: Vec<String>,
    pub is_confidential: bool,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateOAuthClient {
    pub website_id: Uuid,
    pub name: String,
    pub client_type: ClientType,
    pub grant_types: Vec<String>,
    pub redirect_uris: Vec<String>,
    pub scopes: Vec<String>,
    pub is_confidential: bool,
}
