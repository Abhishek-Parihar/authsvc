use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClientType {
    Web,
    Spa,
    Ios,
    Android,
    Service,
}

impl ClientType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Web => "web",
            Self::Spa => "spa",
            Self::Ios => "ios",
            Self::Android => "android",
            Self::Service => "service",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "web" => Some(Self::Web),
            "spa" => Some(Self::Spa),
            "ios" => Some(Self::Ios),
            "android" => Some(Self::Android),
            "service" => Some(Self::Service),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Website {
    pub id: Uuid,
    pub account_id: Uuid,
    pub slug: String,
    pub name: String,
    pub domain: Option<String>,
    pub portal_name: Option<String>,
    pub logo_url: Option<String>,
    pub portal_type: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateWebsite {
    pub account_id: Uuid,
    pub slug: String,
    pub name: String,
    pub domain: Option<String>,
    pub portal_name: Option<String>,
    pub logo_url: Option<String>,
    pub portal_type: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortalInfo {
    pub account_id: Uuid,
    pub account_slug: String,
    pub account_name: String,
    pub website_id: Uuid,
    pub website_slug: String,
    pub website_name: String,
    pub domain: Option<String>,
    pub portal_name: Option<String>,
    pub logo_url: Option<String>,
    pub portal_type: String,
}
