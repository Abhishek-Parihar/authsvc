use async_trait::async_trait;
use authsvc_core::{AuthError, SessionStore};
use deadpool_redis::{Config as RedisConfig, Pool, Runtime};
use deadpool_redis::redis::AsyncCommands;
use uuid::Uuid;

#[derive(Clone)]
pub struct RedisSessionStore {
    pool: Pool,
}

impl RedisSessionStore {
    pub fn new(redis_url: &str) -> Result<Self, AuthError> {
        let cfg = RedisConfig::from_url(redis_url);
        let pool = cfg
            .create_pool(Some(Runtime::Tokio1))
            .map_err(|e| AuthError::Internal(e.to_string()))?;
        Ok(Self { pool })
    }

    pub fn pool(&self) -> &Pool {
        &self.pool
    }

    pub async fn set_json<T: serde::Serialize>(
        &self,
        key: &str,
        value: &T,
        ttl_secs: u64,
    ) -> Result<(), AuthError> {
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| AuthError::Internal(e.to_string()))?;
        let payload =
            serde_json::to_string(value).map_err(|e| AuthError::Internal(e.to_string()))?;
        let _: () = conn
            .set_ex(key, payload, ttl_secs)
            .await
            .map_err(|e| AuthError::Internal(e.to_string()))?;
        Ok(())
    }

    pub async fn get_json<T: serde::de::DeserializeOwned>(&self, key: &str) -> Result<Option<T>, AuthError> {
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| AuthError::Internal(e.to_string()))?;
        let val: Option<String> = conn
            .get(key)
            .await
            .map_err(|e| AuthError::Internal(e.to_string()))?;
        match val {
            Some(s) => Ok(Some(
                serde_json::from_str(&s).map_err(|e| AuthError::Internal(e.to_string()))?,
            )),
            None => Ok(None),
        }
    }

    pub async fn delete_key(&self, key: &str) -> Result<(), AuthError> {
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| AuthError::Internal(e.to_string()))?;
        let _: () = conn
            .del(key)
            .await
            .map_err(|e| AuthError::Internal(e.to_string()))?;
        Ok(())
    }

    fn key(session_id: Uuid) -> String {
        format!("session:{session_id}")
    }
}

#[async_trait]
impl SessionStore for RedisSessionStore {
    async fn create(&self, session_id: Uuid, user_id: Uuid, ttl_secs: u64) -> Result<(), AuthError> {
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| AuthError::Internal(e.to_string()))?;
        let _: () = conn
            .set_ex(Self::key(session_id), user_id.to_string(), ttl_secs)
            .await
            .map_err(|e| AuthError::Internal(e.to_string()))?;
        Ok(())
    }

    async fn get_user_id(&self, session_id: Uuid) -> Result<Option<Uuid>, AuthError> {
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| AuthError::Internal(e.to_string()))?;
        let val: Option<String> = conn
            .get(Self::key(session_id))
            .await
            .map_err(|e| AuthError::Internal(e.to_string()))?;
        match val {
            Some(s) => Ok(Some(
                Uuid::parse_str(&s).map_err(|e| AuthError::Internal(e.to_string()))?,
            )),
            None => Ok(None),
        }
    }

    async fn delete(&self, session_id: Uuid) -> Result<(), AuthError> {
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| AuthError::Internal(e.to_string()))?;
        let _: () = conn
            .del(Self::key(session_id))
            .await
            .map_err(|e| AuthError::Internal(e.to_string()))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};

    #[derive(Serialize, Deserialize, PartialEq, Debug)]
    struct ChallengePayload {
        value: String,
    }

    #[tokio::test]
    async fn json_roundtrip_requires_redis() {
        let Ok(redis_url) = std::env::var("REDIS_URL") else {
            return;
        };
        let store = RedisSessionStore::new(&redis_url).expect("redis");
        let key = format!("test:webauthn:{}", Uuid::new_v4());
        let payload = ChallengePayload {
            value: "challenge-bytes".into(),
        };
        store.set_json(&key, &payload, 30).await.expect("set");
        let loaded: ChallengePayload = store.get_json(&key).await.expect("get").expect("some");
        assert_eq!(loaded, payload);
        store.delete_key(&key).await.expect("del");
    }
}
