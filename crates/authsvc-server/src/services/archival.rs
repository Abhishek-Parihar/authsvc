use std::time::Duration;

use authsvc_core::AuthError;
use deadpool_redis::redis::AsyncCommands;
use uuid::Uuid;

use super::state::AppState;

const LEADER_KEY: &str = "archival:leader";
const LEADER_TTL_SECS: i64 = 55;
const LEASE_TICK_SECS: u64 = 30;
const ARCHIVAL_INTERVAL_SECS: u64 = 3600;

async fn try_acquire_or_renew_leader(state: &AppState, instance_id: &str) -> Result<bool, AuthError> {
    let mut conn = state
        .sessions
        .pool()
        .get()
        .await
        .map_err(|e| AuthError::Internal(e.to_string()))?;

    let acquired: Option<String> = deadpool_redis::redis::cmd("SET")
        .arg(LEADER_KEY)
        .arg(instance_id)
        .arg("NX")
        .arg("EX")
        .arg(LEADER_TTL_SECS)
        .query_async(&mut conn)
        .await
        .map_err(|e| AuthError::Internal(e.to_string()))?;

    if acquired.is_some() {
        return Ok(true);
    }

    let current: Option<String> = conn
        .get(LEADER_KEY)
        .await
        .map_err(|e| AuthError::Internal(e.to_string()))?;

    if current.as_deref() == Some(instance_id) {
        let _: () = conn
            .expire(LEADER_KEY, LEADER_TTL_SECS)
            .await
            .map_err(|e| AuthError::Internal(e.to_string()))?;
        return Ok(true);
    }

    Ok(false)
}

pub async fn run_archival(state: &AppState) -> Result<(), AuthError> {
    let otp = state.repos.postgres().purge_expired_otp_codes().await?;
    let devices = state.repos.postgres().purge_expired_device_codes().await?;
    let tokens = state.repos.postgres().purge_old_refresh_tokens(90).await?;
    let audit_days = state.config.audit_retention_days as i64;
    let dsar_days = state.config.dsar_artifact_retention_days as i64;
    let audit = state
        .repos
        .postgres()
        .purge_old_audit_events(audit_days)
        .await?;
    let dsar = state
        .repos
        .postgres()
        .purge_old_dsar_artifacts(dsar_days)
        .await?;
    tracing::info!(
        otp_purged = otp,
        device_codes_purged = devices,
        tokens_purged = tokens,
        audit_purged = audit,
        dsar_purged = dsar,
        "archival job completed"
    );
    crate::observability::record_archival_run(true);

    if let Ok(Some(age_days)) = state.repos.postgres().active_signing_key_age_days().await {
        if age_days >= state.config.jwt_key_max_age_days as i64 {
            crate::observability::record_jwt_key_age_alert();
            tracing::warn!(
                age_days = age_days,
                max_age_days = state.config.jwt_key_max_age_days,
                "active JWT signing key exceeded max age policy; rotate via POST /v1/keys/rotate"
            );
        }
    }

    Ok(())
}

pub fn spawn_archival_loop(state: AppState) {
    tokio::spawn(async move {
        let instance_id = Uuid::new_v4().to_string();
        let mut lease_interval = tokio::time::interval(Duration::from_secs(LEASE_TICK_SECS));
        let mut archival_interval = tokio::time::interval(Duration::from_secs(ARCHIVAL_INTERVAL_SECS));
        lease_interval.tick().await;
        archival_interval.tick().await;

        loop {
            tokio::select! {
                _ = lease_interval.tick() => {
                    match try_acquire_or_renew_leader(&state, &instance_id).await {
                        Ok(true) => tracing::debug!(instance_id = %instance_id, "archival leader lease held"),
                        Ok(false) => tracing::debug!("archival leader lease held by another instance"),
                        Err(e) => tracing::warn!(error = %e, "archival leader election failed"),
                    }
                }
                _ = archival_interval.tick() => {
                    match try_acquire_or_renew_leader(&state, &instance_id).await {
                        Ok(true) => {
                            if let Err(e) = run_archival(&state).await {
                                tracing::warn!(error = %e, "archival job failed");
                                crate::observability::record_archival_run(false);
                            }
                        }
                        Ok(false) => tracing::debug!("skipping archival; not leader"),
                        Err(e) => tracing::warn!(error = %e, "archival leader election failed"),
                    }
                }
            }
        }
    });
}
