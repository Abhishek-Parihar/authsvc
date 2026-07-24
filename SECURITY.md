# Security Policy

## Supported versions

| Version | Supported          |
| ------- | ------------------ |
| 0.3.x   | :white_check_mark: |
| < 0.3   | :x:                |

Security fixes are released on `main` and backported to the latest minor release when practical. Pin to a [tagged release](https://github.com/Abhishek-Parihar/authsvc/releases) for production.

## Reporting a vulnerability

**Please do not open public GitHub issues for security vulnerabilities.**

### Preferred: GitHub private reporting

Use [GitHub Security Advisories](https://github.com/Abhishek-Parihar/authsvc/security/advisories/new) to report vulnerabilities privately. This is the fastest path for maintainers to triage and coordinate a fix.

### Alternative: email

If you cannot use GitHub advisories, email the repository owner (see GitHub profile contact). Include:

- Affected component (auth flows, SAML, JWT, storage, etc.)
- Steps to reproduce or proof of concept
- Impact assessment
- Suggested fix (if any)

We aim to acknowledge reports within **5 business days** and provide a remediation timeline. Please allow up to **90 days** for a fix before public disclosure, unless we agree otherwise.

## Safe harbor

Good-faith security research that follows this policy will not be pursued legally. Do not:

- Access data belonging to others
- Degrade service availability
- Use social engineering against maintainers or users

## Security practices for deployments

- Run with `ENV=production` and set `DATA_ENCRYPTION_KEY`, JWT keys (or `JWT_KMS_HTTP_URL`), and `ALLOWED_ORIGINS`.
- Use the `authsvc_app` database role in production; audit tables are append-only for the app role.
- Rotate `BOOTSTRAP_SECRET` after initial admin setup.
- Keep dependencies updated: `make security-audit` / `cargo audit`.
- Review [`.cargo/audit.toml`](.cargo/audit.toml) for documented dependency advisories awaiting upstream fixes.
- Review [docs/deploy-production.md](docs/deploy-production.md) before going live.
