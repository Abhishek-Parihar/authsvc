use authsvc_core::AuthError;
use deadpool_redis::redis::AsyncCommands;
use deadpool_redis::Pool;

const WINDOW_SECS: i64 = 60;

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
        self.check_with_limit(key, self.max_per_minute).await
    }

    pub async fn check_with_limit(&self, key: &str, max_per_minute: u32) -> Result<(), AuthError> {
        if max_per_minute == 0 {
            return Ok(());
        }

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
                .expire(&redis_key, WINDOW_SECS)
                .await
                .map_err(|e| AuthError::Internal(e.to_string()))?;
        }

        if count > max_per_minute as i64 {
            crate::observability::record_rate_limit_hit();
            let ttl: i64 = conn
                .ttl(&redis_key)
                .await
                .map_err(|e| AuthError::Internal(e.to_string()))?;
            let retry_after = if ttl > 0 {
                ttl as u64
            } else {
                WINDOW_SECS as u64
            };
            return Err(AuthError::RateLimited(retry_after));
        }
        Ok(())
    }
}
