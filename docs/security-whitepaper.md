# authsvc Security Whitepaper (Summary)

## Architecture
- OAuth 2.0 / OIDC authorization server with account/website multi-tenancy.
- Secrets encrypted at rest via `DataKeyStore` (AES-256-GCM local or KMS proxy).
- JWT signing keys stored in DB (public) with private keys from env/KMS in production.

## Authentication
- Argon2 password hashing, refresh token rotation with reuse detection.
- MFA (TOTP), WebAuthn, magic link, OTP, federated IdP (OIDC + SAML).

## Authorization
- RBAC with optional Casbin/OpenFGA backends.
- Postgres RLS policies on `account_members` and `audit_events`.

## Audit & compliance
- Append-only `audit_events` with webhook/SIEM export.
- DSAR export/delete APIs for privacy compliance.
- `GET /v1/compliance/status` for operational posture.

## Deployment
- Self-hosted: single-tenant defaults, Helm HA (3 replicas, HPA, PDB).
- Managed SaaS: region-pinned data planes via `accounts.region`.
