# Key Compromise Runbook

## Detection
- Unusual JWT signatures, failed JWKS validation, or KMS audit alerts.

## Immediate actions
1. Rotate signing keys: `POST /v1/keys/rotate` (admin).
2. Revoke all active sessions for affected users: `POST /v1/users/{id}/sessions/revoke-all`.
3. Rotate `DATA_ENCRYPTION_KEY` via KMS and re-encrypt webhook/IdP secrets.
4. Invalidate OAuth refresh token families via DB if reuse detected.

## Recovery
- Deploy new JWT keys to all replicas before deactivating old keys (grace period: `JWT_KEY_GRACE_SECS`).
- Notify customers to re-authenticate applications using client credentials.
