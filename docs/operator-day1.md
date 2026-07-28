# Day-1 operator guide

End-to-end checklist for deploying authsvc to production in one sitting.

## Prerequisites

- Kubernetes cluster (or a single VM with Docker)
- PostgreSQL 16+ and Redis 7+
- TLS certificate for your auth domain (e.g. `auth.example.com`)
- Secrets manager or sealed secrets for production credentials

## 1. Generate keys and secrets

```bash
# JWT signing key pair
openssl genrsa -out jwt-private.pem 2048
openssl rsa -in jwt-private.pem -pubout -out jwt-public.pem

# Data encryption key (32+ random bytes, base64)
openssl rand -base64 32

# Bootstrap admin secret (one-time setup)
openssl rand -hex 32

# Metrics bearer token
openssl rand -hex 24
```

## 2. Database setup

```bash
# Create database and application role
psql -h $PGHOST -U postgres <<'SQL'
CREATE USER authsvc_app WITH PASSWORD 'change-me';
CREATE USER authsvc_migrator WITH PASSWORD 'change-me-migrator';
CREATE DATABASE authsvc OWNER authsvc_migrator;
GRANT CONNECT ON DATABASE authsvc TO authsvc_app;
SQL

# Run migrations (use migrator role)
export DATABASE_URL="postgres://authsvc_migrator:change-me-migrator@$PGHOST:5432/authsvc"
cargo run -p authsvc-server -- --migrate-only
# Or set MIGRATE_ONLY=true on first deploy (Helm init container handles this)
```

Set runtime URLs:

| Variable | Role |
|----------|------|
| `DATABASE_URL` | `authsvc_app` — normal queries |
| `DATABASE_MIGRATOR_URL` | `authsvc_migrator` — audit purge / archival only |

## 3. Configure environment

Minimum production variables (see `.env.example` for full list):

```bash
ENV=production
ISSUER=https://auth.example.com
DATABASE_URL=postgres://authsvc_app:...@db:5432/authsvc
DATABASE_MIGRATOR_URL=postgres://authsvc_migrator:...@db:5432/authsvc
REDIS_URL=redis://redis:6379
JWT_PRIVATE_KEY_PEM="$(cat jwt-private.pem)"
JWT_PUBLIC_KEY_PEM="$(cat jwt-public.pem)"
DATA_ENCRYPTION_KEY="<base64-32-bytes>"
BOOTSTRAP_SECRET="<hex-secret>"
METRICS_BEARER_TOKEN="<hex-token>"
ALLOWED_ORIGINS=https://app.example.com
COOKIE_SECURE=true
MIGRATE_ON_START=false
DISABLE_PASSWORD_GRANT=true
```

## 4. Deploy with Helm

```bash
helm upgrade --install authsvc deploy/helm/authsvc \
  -f deploy/helm/authsvc/values-prod.yaml \
  --set env.ISSUER=https://auth.example.com \
  --set ingress.hosts[0].host=auth.example.com
```

Verify:

```bash
curl -sf https://auth.example.com/health
curl -sf https://auth.example.com/.well-known/openid-configuration | jq .issuer
```

## 5. Bootstrap first admin

```bash
curl -X POST https://auth.example.com/v1/auth/register \
  -H "Authorization: Bearer $BOOTSTRAP_SECRET" \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@example.com","password":"<strong-password>","display_name":"Admin"}'
```

After the first user, `/v1/auth/register` requires admin auth. Use the bootstrap secret only for initial setup.

## 6. Create OAuth client

```bash
curl -X POST https://auth.example.com/v1/clients \
  -H "Authorization: Bearer $BOOTSTRAP_SECRET" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "main-app",
    "redirect_uris": ["https://app.example.com/callback"],
    "grant_types": ["authorization_code", "refresh_token"]
  }'
```

Production enforces HTTPS redirect URIs and blocks localhost/private addresses.

## 7. Configure notifications (optional)

See [runbooks/notifications-production.md](./runbooks/notifications-production.md) for SES email and Twilio SMS.

## 8. Open admin console

1. Visit `https://auth.example.com/admin`
2. Paste bootstrap secret or admin JWT in **Settings**
3. Use **Dashboard**, **Users**, **Audit log**, and **SAML IdP** panels

## 9. Post-deploy verification

| Check | Command |
|-------|---------|
| Health | `curl /health` and `/ready` |
| JWKS | `curl /.well-known/jwks.json` |
| Metrics auth | `curl /metrics` → 401 without token |
| OAuth flow | Authorization code flow from your app |
| Audit | Admin → Audit log shows `user.created` |

## 10. Ongoing operations

- **Key rotation:** Admin console or `POST /v1/keys/rotate`
- **Incidents:** [runbooks/](./runbooks/)
- **Performance:** `make perf` locally; nightly SLO gate on `main`
- **Security review:** [security-assessment-checklist.md](./security-assessment-checklist.md)

## Related docs

- [deploy-production.md](./deploy-production.md)
- [helm-deployment.md](./helm-deployment.md)
- [observability.md](./observability.md)
- [SAML.md](./SAML.md)
