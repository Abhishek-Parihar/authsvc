# authsvc v0.2

Plug-and-play Rust authentication and authorization service.

## Features

| Phase | Capability |
|-------|------------|
| **Auth** | Password, client_credentials, refresh_token (rotation + reuse detection), authorization_code + PKCE |
| **OIDC** | Discovery, JWKS, userinfo, introspection, ID tokens |
| **MFA** | TOTP enroll/verify/disable, magic links |
| **Federation** | Google, GitHub, generic OIDC (pluggable `authsvc-idp` crate) |
| **Authz** | RBAC + Casbin/OpenFGA policy adapters (`authsvc-policy`) |
| **Machine** | API keys |
| **Ops** | Audit log, webhooks, JWT key rotation, Helm chart |

## Workspace

```
crates/
├── authsvc-core/      # Domain + ports
├── authsvc-server/    # Axum HTTP server
├── authsvc-client/    # Rust JWKS validator + middleware
├── authsvc-idp/       # Federated identity providers
└── authsvc-policy/    # RBAC, Casbin, OpenFGA backends
sdk/
├── go/authclient/     # Go middleware
├── typescript/        # TS JWKS client stub
└── python/            # Python PyJWT client
deploy/helm/authsvc/   # Kubernetes Helm chart
```

## Quick start

```bash
cp .env.example .env
docker-compose up -d postgres redis
cargo run -p authsvc-server
```

### Bootstrap

```bash
# 1. Create client (bootstrap secret or first-run open registration)
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

# 4. Authz check
curl -s -X POST http://localhost:8080/v1/authz/check \
  -H 'Content-Type: application/json' \
  -d '{"subject_id":"<user_id>","tenant_id":"<tenant_id>","action":"read","resource":"users"}' | jq
```

## Consumer SDKs

### Go

```go
v := authclient.New("http://localhost:8080", "http://localhost:8080/.well-known/jwks.json")
claims, err := v.Validate(ctx, accessToken)
http.Handle("/api/", v.Middleware(apiHandler))
```

### Rust

```rust
use authsvc_client::JwksValidator;
let validator = JwksValidator::new(issuer, jwks_uri);
let claims = validator.validate(&token).await?;
```

### Python

```python
from authsvc_client.validator import JwksValidator
v = JwksValidator("http://localhost:8080", "http://localhost:8080/.well-known/jwks.json")
claims = v.validate(access_token)
```

## Production

- Set `ENV=production` and `JWT_*_KEY_PEM`
- Set `BOOTSTRAP_SECRET` and protect admin routes
- Deploy via `deploy/helm/authsvc/`
- See `api/openapi.yaml` for full API surface

## License

MIT
