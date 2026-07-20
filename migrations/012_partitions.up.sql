-- Scale indexes for archival and future partitioning

CREATE INDEX IF NOT EXISTS idx_refresh_tokens_revoked_expires
    ON refresh_tokens (expires_at)
    WHERE revoked = TRUE;

CREATE INDEX IF NOT EXISTS idx_audit_events_created_at
    ON audit_events (created_at);

COMMENT ON TABLE audit_events IS 'Append-only. For high volume, partition by created_at monthly.';
COMMENT ON TABLE refresh_tokens IS 'Consider partitioning by expires_at for large deployments.';
