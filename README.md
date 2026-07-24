# authsvc

[![CI](https://github.com/Abhishek-Parihar/authsvc/actions/workflows/ci.yml/badge.svg)](https://github.com/Abhishek-Parihar/authsvc/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

**Self-hosted OAuth 2.0 / OpenID Connect authorization server written in Rust.**

authsvc gives you Auth0-style building blocks — login, tokens, MFA, federation, and authorization — without vendor lock-in. Run it behind your apps, own your user data, and integrate via standard OIDC or lightweight SDKs.

## Why authsvc?

| | Commercial IdP (Auth0, Okta) | authsvc |
|---|------------------------------|---------|
| **Hosting** | SaaS only | Self-hosted, your infra |
| **Data ownership** | Vendor-controlled | Your Postgres |
| **Customization** | Plan-limited | Full source access |
| **Stack** | Opaque | Rust + Postgres + Redis |
| **Cost at scale** | Per-MAU pricing | Infra cost only |

Built for teams that want a **credible auth foundation** for multiple apps under one organization — not a full commercial identity platform with hosted UI and billing.

## Features

| Area | Capability |
|------|------------|
| **Auth** | Password, client credentials, refresh token (rotation + reuse detection), authorization code + PKCE, API key grant |
| **OIDC** | Discovery, JWKS (multi-key + grace period), userinfo, introspection, ID tokens |
| **MFA** | TOTP, magic links, WebAuthn/passkeys, email & phone OTP |
| **Federation** | Google, GitHub, Microsoft, generic OIDC, SAML 2.0 SP |
| **Authz** | RBAC with role hierarchy, Casbin, OpenFGA adapter |
| **Platform** | Accounts → websites → members (multi-app tenancy) |
| **Enterprise** | SCIM, DSAR export/delete, session management, append-only audit log |
| **Ops** | Helm chart, distroless Docker, Prometheus, OpenTelemetry |

## Architecture

```
┌─────────────┐     ┌──────────────────────────────────────┐
│  Your apps  │────▶│           authsvc-server           │
│  (OIDC/SDK) │     │  handlers → services → stores      │
└─────────────┘     └──────┬───────────────┬─────────────┘
                           │               │
                    ┌──────▼──────┐  ┌─────▼─────┐
                    │  PostgreSQL │  │   Redis   │
                    │ users, RBAC │  │ sessions, │
                    │ audit, keys │  │ rate limit│
                    └─────────────┘  └───────────┘
```

Crate layout:

```
crates/
├── authsvc-core/      # Domain types + repository ports
├── authsvc-server/    # Axum HTTP server
├── authsvc-client/    # Rust JWKS validator + middleware
├── authsvc-idp/       # Federated identity providers
└── authsvc-policy/    # RBAC, Casbin, OpenFGA backends
sdk/                   # Go, TypeScript, Python clients
```

## Quick start

### Prerequisites

- [Rust](https://rustup.rs) (stable)
- PostgreSQL 16+ and Redis 7+

### Run locally

```bash
git clone https://github.com/Abhishek-Parihar/authsvc.git
cd authsvc
brew install postgresql@18 redis   # or use Docker Compose
make brew-up
cp .env.example .env
cargo run -p authsvc-server
```

Server listens on `http://localhost:8080`. Migrations run automatically on startup.

### Bootstrap

```bash
# 1. Create OAuth client
curl -s -X POST http://localhost:8080/v1/clients \
  -H "Authorization: Bearer $BOOTSTRAP_SECRET" \
  -H 'Content-Type: application/json' \
  -d '{"name":"my-app","redirect_uris":["http://localhost:3000/callback"]}' | jq

# 2. Register first user (open when no users exist)
curl -s -X POST http://localhost:8080/v1/auth/register \
  -H 'Content-Type: application/json' \
  -d '{"email":"admin@example.com","password":"securepass123"}' | jq

# 3. Get tokens
curl -s -X POST http://localhost:8080/oauth/token \
  -H 'Content-Type: application/json' \
  -d '{"grant_type":"password","client_id":"<id>","username":"admin@example.com","password":"securepass123"}' | jq

# 4. Check authorization
curl -s -X POST http://localhost:8080/v1/authz/check \
  -H 'Content-Type: application/json' \
  -d '{"subject_id":"<user_id>","account_id":"<account_id>","action":"read","resource":"users"}' | jq
```

See [api/openapi.yaml](api/openapi.yaml) for the full API surface.

## Configuration

Copy [`.env.example`](.env.example) and adjust. Key production variables:

| Variable | Purpose |
|----------|---------|
| `ENV=production` | Enables production defaults (e.g. disables password grant) |
| `JWT_PRIVATE_KEY_PEM` / `JWT_PUBLIC_KEY_PEM` | JWT signing keys |
| `DATA_ENCRYPTION_KEY` | Encrypts MFA secrets, IdP configs, stored keys |
| `BOOTSTRAP_SECRET` | Protects admin/bootstrap routes |
| `ALLOWED_ORIGINS` | CORS allowlist |

Full reference: [docs/deploy-production.md](docs/deploy-production.md).

## Consumer SDKs

**Rust** — `authsvc-client` crate with JWKS validator and Axum middleware.

**Go** — `sdk/go/authclient` with middleware.

**TypeScript** — `sdk/typescript` (`@authsvc/client`).

**Python** — `sdk/python/authsvc_client`.

Permissions are intentionally **not** embedded in JWT access tokens. Call `/v1/authz/check` for fine-grained authorization.

## Production deployment

```bash
docker build -t authsvc .
helm install authsvc deploy/helm/authsvc/ \
  --set secrets.jwtPublicKeyPem="..." \
  --set secrets.dataEncryptionKey="..." \
  --set secrets.bootstrapSecret="..."
```

- Distroless, non-root container image
- Helm: 3 replicas, HPA, PDB, init-container migrations
- See [docs/deploy-production.md](docs/deploy-production.md) and [docs/helm-deployment.md](docs/helm-deployment.md)

## Documentation

| Doc | Description |
|-----|-------------|
| [docs/README.md](docs/README.md) | Documentation index |
| [docs/deploy-production.md](docs/deploy-production.md) | Production hardening |
| [docs/SAML.md](docs/SAML.md) | SAML SP configuration |
| [docs/security-whitepaper.md](docs/security-whitepaper.md) | Security architecture summary |
| [docs/observability.md](docs/observability.md) | Metrics and tracing |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Development guide |
| [SECURITY.md](SECURITY.md) | Vulnerability reporting |

## Scope

**In scope:** OAuth/OIDC server, MFA, federation, RBAC/Casbin/OpenFGA, multi-app tenancy, SCIM, audit, Helm deployment.

**Out of scope (for now):** Hosted login UI, gRPC gateway, commercial multi-tenant billing. Contributions welcome — see [CONTRIBUTING.md](CONTRIBUTING.md).

## Development

```bash
make test          # run full test suite
make fmt           # format
make lint          # clippy
make security-audit
```

Integration tests use Postgres and Redis (Homebrew or testcontainers). Run with `--test-threads=1` to avoid env races.

## License

[MIT](LICENSE) — see [LICENSE](LICENSE) for details.

## Security

Report vulnerabilities privately per [SECURITY.md](SECURITY.md). Do not open public issues for security bugs.
