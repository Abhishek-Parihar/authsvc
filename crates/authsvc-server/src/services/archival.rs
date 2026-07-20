use authsvc_core::AuthError;

use super::state::AppState;

pub async fn run_archival(state: &AppState) -> Result<(), AuthError> {
    let otp = state.repos.postgres().purge_expired_otp_codes().await?;
    let tokens = state.repos.postgres().purge_old_refresh_tokens(90).await?;
    tracing::info!(otp_purged = otp, tokens_purged = tokens, "archival job completed");
    Ok(())
}

pub fn spawn_archival_loop(state: AppState) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(3600));
        loop {
            interval.tick().await;
            if let Err(e) = run_archival(&state).await {
                tracing::warn!(error = %e, "archival job failed");
            }
        }
    });
}
