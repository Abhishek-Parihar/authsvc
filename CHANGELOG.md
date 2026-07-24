# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Open-source documentation: `LICENSE`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, GitHub issue/PR templates.
- Documentation index at `docs/README.md`.

## [0.3.0] - 2026-07-20

### Added

- OAuth 2.0 / OIDC authorization server with discovery, JWKS, userinfo, and introspection.
- Grants: authorization code + PKCE, refresh token (rotation + reuse detection), client credentials, API key, password (dev only).
- MFA: TOTP, magic links, WebAuthn/passkeys, email and phone OTP.
- Federation: Google, GitHub, Microsoft, generic OIDC, SAML 2.0 Service Provider.
- Authorization: RBAC with role hierarchy, Casbin, and OpenFGA backends.
- Platform model: accounts, websites, memberships, and per-website OAuth clients.
- Enterprise: SCIM provisioning, DSAR export/delete, session management, append-only audit log.
- Operations: Helm chart, distroless Docker image, Prometheus metrics, OpenTelemetry hooks.
- Consumer SDKs: Rust, Go, TypeScript, and Python.

### Security

- Argon2 password hashing, AES-256-GCM encryption at rest, JWT key rotation with grace period.
- Postgres row-level security, account lockout, rate limiting, production hardening guide.

[Unreleased]: https://github.com/Abhishek-Parihar/authsvc/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/Abhishek-Parihar/authsvc/releases/tag/v0.3.0
