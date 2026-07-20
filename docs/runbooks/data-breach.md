# Data Breach Runbook

## Containment
1. Enable account lockdown: set `locked_until` on affected users.
2. Disable compromised IdP configs: `DELETE /v1/idp-configs/{provider}`.
3. Revoke API keys and SCIM tokens for the account.

## Evidence
- Export audit events via `audit.*` webhooks or SIEM (`AUDIT_EXPORT_WEBHOOK`).
- Preserve `audit_events` — table is append-only in production.

## Notification
- Follow legal/DPA requirements for customer notification timelines.
