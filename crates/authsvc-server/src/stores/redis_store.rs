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
