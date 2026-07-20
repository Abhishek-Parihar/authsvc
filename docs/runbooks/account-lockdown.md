# Account Lockdown Runbook

## Per-account lockdown
1. Set `enforce_mfa = true` on the account (blocks login without MFA).
2. Revoke all user sessions: `POST /v1/users/{id}/sessions/revoke-all`.
3. Disable webhooks and rotate SCIM tokens.
4. Optionally set `rate_limit_override` to throttle the account.

## Platform-wide
- Set `DISABLE_PASSWORD_GRANT=true` and deploy.
- Scale down affected region data plane (managed SaaS).
