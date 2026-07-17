# authsvc

A standalone, plug-and-play authentication and authorization service written in Rust.

**authsvc** provides OIDC-compatible token issuance, password authentication, client credentials, refresh token rotation with reuse detection, and RBAC authorization checks — consumable by any language via HTTP.

## Features

| Area | Supported |
|------|-----------|
| **Authentication** | Password login, OAuth2 client credentials, refresh tokens |
| **OIDC** | Discovery document, JWKS, token/revocation endpoints |
| **Authorization** | RBAC with `POST /v1/authz/check` |
| **Tokens** | RS256 JWT access tokens, rotating refresh tokens |
| **Multi-tenant** | Tenant-scoped users, roles, and permissions |
| **Sessions** | Redis-backed session store (for future browser flows) |
| **Client library** | `authsvc-client` crate — JWKS-based token validation |

### Roadmap (plug-in interfaces ready)

- Federated IdPs (Google, GitHub, SAML, generic OIDC)
- WebAuthn / passkeys
- TOTP MFA
- Magic links
- ABAC/ReBAC policy adapters (Casbin, OpenFGA)

## Quick start

### Prerequisites

- Rust 1.75+ (`rustup`)
- Docker (for Postgres + Redis)

### Local development

```bash
cp .env.example .env
make docker-up          # starts Postgres + Redis
cargo run -p authsvc-server
```

### Bootstrap flow

```bash
# 1. Create an OAuth client
curl -s -X POST http://localhost:8080/v1/clients \
  -H 'Content-Type: application/json' \
  -d '{"name":"my-app"}' | jq

# 2. Register a user
curl -s -X POST http://localhost:8080/v1/auth/register \
  -H 'Content-Type: application/json' \
  -d '{"email":"admin@example.com","password":"securepass123","display_name":"Admin"}' | jq

# 3. Get tokens (password grant)
curl -s -X POST http://localhost:8080/oauth/token \
  -H 'Content-Type: application/json' \
  -d '{
    "grant_type": "password",
    "client_id": "<client_id>",
    "username": "admin@example.com",
    "password": "securepass123"
  }' | jq

# 4. Check authorization
curl -s -X POST http://localhost:8080/v1/authz/check \
  -H 'Content-Type: application/json' \
  -d '{
    "subject_id": "<user_id>",
    "tenant_id": "<tenant_id>",
    "action": "read",
    "resource": "users"
  }' | jq
```

### OIDC discovery

```bash
curl http://localhost:8080/.well-known/openid-configuration | jq
curl http://localhost:8080/.well-known/jwks.json | jq
```

## Architecture

```
crates/
├── authsvc-core/     Domain models, ports (repository traits), errors
├── authsvc-server/   Axum HTTP server, Postgres + Redis adapters
└── authsvc-client/   JWKS validator for consumer services
```

Hexagonal layout — swap Postgres for another store, add IdP adapters under `adapters/idp/`, or plug in an external policy engine without touching HTTP handlers.

## Configuration

See `.env.example`. Key variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `AUTHSVC_ISSUER` | `http://localhost:8080` | OIDC issuer URL |
| `DATABASE_URL` | — | Postgres connection string |
| `REDIS_URL` | `redis://127.0.0.1:6379` | Redis for sessions |
| `JWT_PRIVATE_KEY_PEM` | auto-generated | RSA private key (set in prod) |
| `JWT_PUBLIC_KEY_PEM` | auto-generated | RSA public key (set in prod) |

## Consumer integration

Use `authsvc-client` in any Rust service:

```rust
use authsvc_client::JwksValidator;

let validator = JwksValidator::new(
    "http://localhost:8080",
    "http://localhost:8080/.well-known/jwks.json",
);
let claims = validator.validate(&access_token).await?;
```

For Go, Node, Python, etc. — validate JWTs locally using the JWKS endpoint. No SDK required.

## Docker

```bash
docker compose up --build
```

## License

MIT
