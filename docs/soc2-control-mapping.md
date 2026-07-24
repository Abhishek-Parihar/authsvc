# SOC 2 Control Mapping (authsvc)

| SOC 2 Criteria | authsvc Control |
|----------------|-----------------|
| CC6.1 Logical access | RBAC/Casbin, admin API keys, MFA enforcement per account |
| CC6.6 Encryption | DataKeyStore for MFA/webhook/IdP secrets; TLS in production |
| CC6.7 Credential management | Argon2, refresh rotation, session revoke API |
| CC7.2 Monitoring | Audit events, Prometheus metrics, OTEL tracing |
| CC7.3 Incident response | Runbooks in `docs/runbooks/` |
| CC8.1 Change management | Helm init-container migrations, key rotation API |
| P4.2 Data retention | Archival job (OTP purge, revoked token cleanup, audit retention, DSAR artifact purge) |
| P4.3 Disposal | DSAR delete API with PII anonymization and complete erasure |

## Evidence sources

| Control area | Evidence location |
|--------------|-------------------|
| Access control | `account_members`, RBAC/Casbin policy tables, `GET /v1/compliance/status` |
| Encryption at rest | `DataKeyStore` usage in MFA/webhook/IdP secret stores; `jwt_signing_keys` table |
| Credential lifecycle | `refresh_tokens` rotation/revocation, `sessions` Redis keys, lockout counters |
| Audit logging | `audit_events` table (append-only in production via migration `016_audit_append_only`) |
| Audit export | `AUDIT_EXPORT_WEBHOOK` SIEM delivery with 3-attempt retry in `services/state.rs` |
| Webhook delivery | `webhook_deliveries` table, `webhook.failed` audit events |
| Data retention | Hourly archival job in `services/archival.rs`; `AUDIT_RETENTION_DAYS`, `DSAR_ARTIFACT_RETENTION_DAYS` config |
| DSAR / erasure | `GET /v1/users/{id}/export`, `DELETE /v1/users/{id}/privacy`, `data_export_requests` table |
| Complete erasure | `complete_erasure` in `stores/extended/privacy.rs` (identities, MFA, WebAuthn, memberships, export artifacts) |
| Monitoring | Prometheus metrics endpoint, OTEL tracing (`OTEL_ENDPOINT`), structured logs |
| Change management | SQL migrations in `migrations/`, Helm init-container per `docs/deploy-production.md` |
| Incident response | Runbooks under `docs/runbooks/` |
| Automated tests | `crates/authsvc-server/tests/compliance_test.rs`, `integration_test.rs` |
