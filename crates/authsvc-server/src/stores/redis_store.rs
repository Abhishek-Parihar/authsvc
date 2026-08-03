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

    fn user_index_key(user_id: Uuid) -> String {
        format!("user_sessions:{user_id}")
    }
}

#[async_trait]
impl authsvc_core::CacheStore for RedisSessionStore {
    async fn set_json<T>(&self, key: &str, value: &T, ttl_secs: u64) -> Result<(), AuthError>
    where
        T: serde::Serialize + Send + Sync,
    {
        self.set_json(key, value, ttl_secs).await
    }

    async fn get_json<T>(&self, key: &str) -> Result<Option<T>, AuthError>
    where
        T: serde::de::DeserializeOwned + Send,
    {
        self.get_json(key).await
    }

    async fn delete_key(&self, key: &str) -> Result<(), AuthError> {
        self.delete_key(key).await
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
        let session_key = Self::key(session_id);
        let index_key = Self::user_index_key(user_id);
        let _: () = conn
            .set_ex(&session_key, user_id.to_string(), ttl_secs)
            .await
            .map_err(|e| AuthError::Internal(e.to_string()))?;
        let _: () = conn
            .sadd(&index_key, session_id.to_string())
            .await
            .map_err(|e| AuthError::Internal(e.to_string()))?;
        let _: () = conn
            .expire(&index_key, ttl_secs as i64)
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
        let session_key = Self::key(session_id);
        let user_id: Option<String> = conn
            .get(&session_key)
            .await
            .map_err(|e| AuthError::Internal(e.to_string()))?;
        if let Some(user_id) = user_id {
            if let Ok(user_uuid) = Uuid::parse_str(&user_id) {
                let index_key = Self::user_index_key(user_uuid);
                let _: () = conn
                    .srem(&index_key, session_id.to_string())
                    .await
                    .map_err(|e| AuthError::Internal(e.to_string()))?;
            }
        }
        let _: () = conn
            .del(session_key)
            .await
            .map_err(|e| AuthError::Internal(e.to_string()))?;
        Ok(())
    }

    async fn list_for_user(&self, user_id: Uuid) -> Result<Vec<Uuid>, AuthError> {
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| AuthError::Internal(e.to_string()))?;
        let index_key = Self::user_index_key(user_id);
        let members: Vec<String> = conn
            .smembers(&index_key)
            .await
            .map_err(|e| AuthError::Internal(e.to_string()))?;
        let mut session_ids = Vec::with_capacity(members.len());
        for member in members {
            match Uuid::parse_str(&member) {
                Ok(id) => session_ids.push(id),
                Err(_) => {
                    let _: () = conn
                        .srem(&index_key, member)
                        .await
                        .map_err(|e| AuthError::Internal(e.to_string()))?;
                }
            }
        }
        Ok(session_ids)
    }
}

impl RedisSessionStore {
    pub async fn revoke_all_for_user(&self, user_id: Uuid) -> Result<u64, AuthError> {
        let session_ids = SessionStore::list_for_user(self, user_id).await?;
        let mut count = 0u64;
        for session_id in session_ids {
            SessionStore::delete(self, session_id).await?;
            count += 1;
        }

        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| AuthError::Internal(e.to_string()))?;

        let user_id_str = user_id.to_string();
        let mut cursor = 0u64;
        loop {
            let scan: (u64, Vec<String>) = deadpool_redis::redis::cmd("SCAN")
                .arg(cursor)
                .arg("MATCH")
                .arg("session:*")
                .arg("COUNT")
                .arg(128)
                .query_async(&mut conn)
                .await
                .map_err(|e| AuthError::Internal(e.to_string()))?;
            cursor = scan.0;
            for key in scan.1 {
                let val: Option<String> = conn
                    .get(&key)
                    .await
                    .map_err(|e| AuthError::Internal(e.to_string()))?;
                if val.as_deref() == Some(user_id_str.as_str()) {
                    let _: () = conn
                        .del(&key)
                        .await
                        .map_err(|e| AuthError::Internal(e.to_string()))?;
                    count += 1;
                }
            }
            if cursor == 0 {
                break;
            }
        }

        let index_key = Self::user_index_key(user_id);
        let _: () = conn
            .del(index_key)
            .await
            .map_err(|e| AuthError::Internal(e.to_string()))?;

        Ok(count)
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
