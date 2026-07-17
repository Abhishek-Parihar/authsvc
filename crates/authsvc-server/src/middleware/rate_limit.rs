use authsvc_core::AuthError;
use deadpool_redis::redis::AsyncCommands;
use deadpool_redis::Pool;

#[derive(Clone)]
pub struct RateLimiter {
    pool: Pool,
    max_per_minute: u32,
}

impl RateLimiter {
    pub fn new(pool: Pool, max_per_minute: u32) -> Self {
        Self {
            pool,
            max_per_minute,
        }
    }

    pub async fn check(&self, key: &str) -> Result<(), AuthError> {
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| AuthError::Internal(e.to_string()))?;

        let redis_key = format!("ratelimit:{key}");
        let count: i64 = conn
            .incr(&redis_key, 1)
            .await
            .map_err(|e| AuthError::Internal(e.to_string()))?;

        if count == 1 {
            let _: () = conn
                .expire(&redis_key, 60)
                .await
                .map_err(|e| AuthError::Internal(e.to_string()))?;
        }

        if count > self.max_per_minute as i64 {
            return Err(AuthError::Forbidden);
        }
        Ok(())
    }
}
