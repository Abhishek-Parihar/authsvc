# Internal penetration test report

**Date:** 2026-08-03 (updated)  
**Scope:** authsvc v0.3.0  
**Method:** Manual code review, `security_test.rs`, exploit validation

## Executive summary

| Severity | Found | Fixed |
|----------|-------|-------|
| Critical | 0 | — |
| High | 1 | 1 |
| Medium | 5 | 5 |
| Low | 4 | 4 |
| Info | 3 | 1 |

**Verdict:** All actionable findings fixed. Schedule external pen-test before customer-facing production at scale.

## Findings

### HIGH — Open redirect on `/oauth/logout` ✅ FIXED

Require `client_id` or validated `id_token_hint` before honoring `post_logout_redirect_uri`. Test: `logout_open_redirect_rejected`.

### MEDIUM — Bootstrap admin session outlives secret removal ✅ FIXED

Production bootstrap sessions re-check `ALLOW_BOOTSTRAP_SECRET` on each request.

### MEDIUM — Device approval brute-force ✅ FIXED

Rate limit `device_approve:{email}`.

### MEDIUM — MFA completion brute-force ✅ FIXED

Rate limit `mfa_complete:{challenge_id}`.

### MEDIUM — Stale RBAC in JWT permissions ✅ FIXED

Role assignment revokes all refresh tokens for the user, forcing re-auth with updated permissions when `INCLUDE_PERMISSIONS_IN_JWT` is enabled.

### MEDIUM — Custom URI scheme redirects ✅ FIXED

Custom schemes (`myapp://`) blocked in production unless `ALLOW_CUSTOM_SCHEME_REDIRECTS=true`.

### LOW — `AUDIT_EXPORT_WEBHOOK` SSRF ✅ FIXED

Validated at production startup via `validate_webhook_url`.

### LOW — Outbound HTTP no timeouts ✅ FIXED

Shared `http_client::outbound_client()` — 10s connect, 30s request timeout on webhooks, audit export, KMS, notifications.

### LOW — Device approve CSRF ✅ FIXED

One-time CSRF token in Redis, embedded in device form. Test: `device_approve_requires_csrf`.

### INFO — SCIM bearer tokens ✅ DOCUMENTED

See [runbooks/scim-token-rotation.md](./runbooks/scim-token-rotation.md).

## Automated tests

`security_test.rs` (10 tests): admin RBAC, metrics auth, webhook SSRF, authz auth, introspect, API key scope, admin cookie session, logout redirect, device CSRF.

## Related

- [security-assessment-checklist.md](./security-assessment-checklist.md)
- [SECURITY.md](../SECURITY.md)
