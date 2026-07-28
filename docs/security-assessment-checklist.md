# Security assessment checklist

Self-assessment checklist for security reviews, vendor questionnaires, and pre-audit preparation. This is **not** a certification — use it to demonstrate control coverage and identify gaps before a formal pen-test or SOC 2 audit.

## Authentication & session management

| Control | Status | Evidence |
|---------|--------|----------|
| Passwords hashed with Argon2id | ✅ | `crates/authsvc-server/src/crypto/password.rs` |
| Account lockout after failed attempts | ✅ | `LOCKOUT_MAX_ATTEMPTS`, `stores/` |
| Refresh token rotation + reuse detection | ✅ | `services/oidc_flow.rs`, integration tests |
| PKCE required (S256) for auth code flow | ✅ | `services/oidc_flow.rs` |
| Secure session cookies (HttpOnly, SameSite) | ✅ | `handlers/oidc.rs` |
| MFA (TOTP, email/phone OTP, magic link) | ✅ | `handlers/auth.rs` |
| WebAuthn / passkeys | ✅ | `handlers/webauthn.rs` |
| Device authorization grant (RFC 8628) | ✅ | `services/device_flow.rs` |

## Cryptography

| Control | Status | Evidence |
|---------|--------|----------|
| JWT signed RS256 | ✅ | `crypto/jwt.rs` |
| JWT keys encrypted at rest in DB | ✅ | migration `015_jwt_keys_encrypted` |
| Optional external KMS for signing | ✅ | `JWT_KMS_HTTP_URL` |
| Data encryption key for secrets/MFA | ✅ | `DATA_ENCRYPTION_KEY`, `crypto/data_keys.rs` |
| Key rotation API | ✅ | `POST /v1/keys/rotate` |

## Authorization & multi-tenancy

| Control | Status | Evidence |
|---------|--------|----------|
| Row-level security (RLS) on tenant data | ✅ | migrations `013`, `017`, `018`, `019` |
| RBAC + optional Casbin/OpenFGA | ✅ | `authsvc-policy/` |
| Admin routes require admin permission | ✅ | `middleware/admin.rs` |
| SCIM provisioning with bearer tokens | ✅ | `handlers/scim.rs` |

## Input validation & SSRF

| Control | Status | Evidence |
|---------|--------|----------|
| OAuth redirect URI allowlist | ✅ | `security/redirect_uri.rs` |
| Production HTTPS-only redirect URIs | ✅ | `validate_redirect_uri_format` |
| Block localhost/private redirect URIs (prod) | ✅ | `security/host.rs` |
| Webhook URL SSRF protection | ✅ | `security/webhook_url.rs` |
| DNS rebinding check on webhook hosts | ✅ | `validate_resolved_host` |
| SAML ACS URL validation | ✅ | `services/saml_idp.rs` |

## Audit & compliance

| Control | Status | Evidence |
|---------|--------|----------|
| Append-only audit log | ✅ | migration `016_audit_append_only` |
| Audit events for login/register/admin | ✅ | `services/state.rs` `audit()` |
| DSAR export / right to erasure | ✅ | `handlers/privacy.rs` |
| SOC 2 control mapping (reference) | ✅ | `docs/soc2-control-mapping.md` |

## Infrastructure & operations

| Control | Status | Evidence |
|---------|--------|----------|
| Production config validation | ✅ | `config.rs` |
| Metrics endpoint bearer auth (prod) | ✅ | `middleware/metrics_auth.rs` |
| Security headers (CSP, HSTS) | ✅ | `middleware/security.rs` |
| Rate limiting (Redis) | ✅ | `middleware/rate_limit.rs` |
| Graceful shutdown | ✅ | `main.rs` |
| Container image scanning (Trivy) | ✅ | `.github/workflows/ci.yml` |
| Dependency audit (cargo-audit) | ✅ | CI `security-audit` job |
| Perf SLO regression gate | ✅ | `scripts/perf_test.sh`, nightly workflow |

## Incident response

| Control | Status | Evidence |
|---------|--------|----------|
| Key compromise runbook | ✅ | `docs/runbooks/key-compromise.md` |
| Account lockdown runbook | ✅ | `docs/runbooks/account-lockdown.md` |
| Data breach runbook | ✅ | `docs/runbooks/data-breach.md` |
| Notifications production runbook | ✅ | `docs/runbooks/notifications-production.md` |

## Known gaps (pre-audit)

| Gap | Mitigation plan |
|-----|-----------------|
| No third-party pen-test report | Schedule annual pen-test; attach report here |
| No formal SOC 2 Type II | Use control mapping; engage auditor when ready |
| Admin UI uses localStorage for token | Prefer short-lived JWT; restrict admin to VPN/IP allowlist |
| Custom URI scheme redirects not DNS-checked | Accept risk for native apps; document in client onboarding |
| Password grant available in dev | Disabled in production via `DISABLE_PASSWORD_GRANT` |

## Review cadence

- **Quarterly:** Re-run this checklist; update evidence links
- **On release:** Verify CI (tests, audit, Trivy) green
- **Annually:** External pen-test; rotate all long-lived secrets

## Related

- [security-whitepaper.md](./security-whitepaper.md)
- [operator-day1.md](./operator-day1.md)
- [SECURITY.md](../SECURITY.md) — vulnerability reporting
