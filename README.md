# authsvc v0.3

Plug-and-play Rust authentication and authorization service.

## Features

| Phase | Capability |
|-------|------------|
| **Auth** | Password, client_credentials, refresh_token (rotation + reuse detection), authorization_code + PKCE, **api_key grant** |
| **OIDC** | Discovery, JWKS (multi-key + grace period), userinfo, introspection, ID tokens |
| **MFA** | TOTP enroll/verify/disable, magic links (log or SMTP HTTP relay) |
| **Federation** | Google, GitHub, generic OIDC (pluggable `authsvc-idp` crate) |
| **Authz** | RBAC with **role hierarchy**, real **Casbin** policies, OpenFGA adapter |
| **Machine** | API keys (`Authorization: ApiKey` or `X-Api-Key`, `grant_type=api_key`) |
| **Ops** | Audit log, **webhook retries**, JWT key rotation with hot reload, Helm + kind local k8s |

## Workspace

```
crates/
├── authsvc-core/      # Domain + ports (incl. NotificationSender)
├── authsvc-server/    # Axum HTTP server
├── authsvc-client/    # Rust JWKS validator + middleware
├── authsvc-idp/       # Federated identity providers
└── authsvc-policy/    # RBAC, Casbin, OpenFGA backends
sdk/
├── go/authclient/     # Go middleware
├── typescript/        # TS SDK (jose + ApiKeyClient)
└── python/            # Python PyJWT client
deploy/helm/authsvc/   # Kubernetes Helm chart (optional Ingress)
deploy/kind/           # Local kind cluster values
scripts/               # perf_test.sh, k8s_local_up.sh, k8s_perf_test.sh
```

## Quick start (Homebrew — default)

Requires [Homebrew](https://brew.sh) Postgres and Redis:

```bash
brew install postgresql@18 redis
make brew-up          # start services + create authsvc DB
cp .env.example .env
cargo run -p authsvc-server
```

Or use the script directly: `./scripts/brew_services.sh up|down|status`

**Connection URLs:** `postgres://authsvc:authsvc@127.0.0.1:5432/authsvc` and `redis://127.0.0.1:6379`

### Optional: Docker Compose

```bash
docker compose up -d postgres redis
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

# 3. Get tokens (password grant)
curl -s -X POST http://localhost:8080/oauth/token \
  -H 'Content-Type: application/json' \
  -d '{"grant_type":"password","client_id":"<id>","username":"admin@example.com","password":"securepass123"}' | jq

# 4. API key grant
curl -s -X POST http://localhost:8080/oauth/token \
  -H 'Content-Type: application/json' \
  -d '{"grant_type":"api_key","api_key":"ak_..."}' | jq

# 5. Authz check
curl -s -X POST http://localhost:8080/v1/authz/check \
  -H 'Content-Type: application/json' \
  -d '{"subject_id":"<user_id>","account_id":"<account_id>","action":"read","resource":"users"}' | jq
```

## Environment

| Variable | Description |
|----------|-------------|
| `JWT_PRIVATE_KEY_PEM` / `JWT_PUBLIC_KEY_PEM` | Required in production; persisted to `signing_keys` on first boot |
| `JWT_KEY_GRACE_SECS` | How long rotated public keys stay in JWKS (default `86400`) |
| `POLICY_BACKEND` | `rbac` (default), `casbin`, or `openfga` |
| `SMTP_URL` | Optional HTTP mail relay for magic links (`SMTP_FROM` optional) |
| `BOOTSTRAP_SECRET` | Admin bootstrap bearer token |

Permissions are **not** embedded in JWT access tokens; use `/v1/authz/check` for fine-grained authorization.

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

### TypeScript

```bash
cd sdk/typescript && npm install && npm run build
```

```typescript
import { JwksValidator, ApiKeyClient } from "@authsvc/client";
const v = new JwksValidator("http://localhost:8080", "http://localhost:8080/.well-known/jwks.json");
const claims = await v.validate(accessToken);
```

### Python

```python
from authsvc_client.validator import JwksValidator
v = JwksValidator("http://localhost:8080", "http://localhost:8080/.well-known/jwks.json")
claims = v.validate(access_token)
```

## Production

- Set `ENV=production` and `JWT_*_KEY_PEM` (or rely on DB-backed keys after first persist)
- Set `BOOTSTRAP_SECRET` and protect admin routes
- Deploy via `deploy/helm/authsvc/` — enable `ingress.enabled`, set `secrets.jwt*`, memory `1Gi` recommended
- Distroless non-root Docker image: `docker build -t authsvc .`
- See `api/openapi.yaml` for full API surface

## Local Kubernetes (kind)

```bash
./scripts/k8s_local_up.sh
./scripts/k8s_perf_test.sh
./scripts/k8s_local_down.sh
```

## Out of scope

SAML, gRPC gateway, admin UI, and vananam platform integration are documented as future work.

## License

MIT
