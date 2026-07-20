# SOC 2 Control Mapping (authsvc)

| SOC 2 Criteria | authsvc Control |
|----------------|-----------------|
| CC6.1 Logical access | RBAC/Casbin, admin API keys, MFA enforcement per account |
| CC6.6 Encryption | DataKeyStore for MFA/webhook/IdP secrets; TLS in production |
| CC6.7 Credential management | Argon2, refresh rotation, session revoke API |
| CC7.2 Monitoring | Audit events, Prometheus metrics, OTEL tracing |
| CC7.3 Incident response | Runbooks in `docs/runbooks/` |
| CC8.1 Change management | Helm init-container migrations, key rotation API |
| P4.2 Data retention | Archival job (OTP purge, revoked token cleanup) |
| P4.3 Disposal | DSAR delete API with PII anonymization |
