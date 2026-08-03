# Helm deployment

Deploy authsvc to Kubernetes with the chart in `deploy/helm/authsvc`.

## Prerequisites

- Kubernetes 1.25+
- Helm 3
- Postgres and Redis reachable from the cluster (or install separately)
- TLS certificate for ingress (production)

## Quick start

```bash
# Render production manifests locally (no cluster required)
make helm-template

# Install with production values (see values-prod.yaml header for --set secrets)
helm upgrade --install authsvc deploy/helm/authsvc \
  -f deploy/helm/authsvc/values-prod.yaml \
  --namespace authsvc --create-namespace

# Post-deploy verification
export AUTHSVC_URL=https://auth.example.com
export EXPECTED_ISSUER=https://auth.example.com
export METRICS_BEARER_TOKEN=...
export ADMIN_ACCESS_TOKEN=...   # optional admin JWT
make verify-production
```

See `deploy/helm/authsvc/values-prod.yaml` for the full production values template.

```bash
# Install with overrides
helm upgrade --install authsvc deploy/helm/authsvc \
  -f deploy/helm/authsvc/values.yaml \
  --set secrets.databaseUrl="postgres://..." \
  --set secrets.redisUrl="redis://..." \
  --set secrets.dataEncryptionKey="$(openssl rand -base64 32)" \
  --set env.ISSUER="https://auth.example.com" \
  --set env.ALLOWED_ORIGINS="https://app.example.com"
```

## Required secrets

Set these via `--set`, a values file, or an external secret manager:

| Value key | Env var | Notes |
|-----------|---------|-------|
| `secrets.databaseUrl` | `DATABASE_URL` | App role (`authsvc_app`) in production |
| `secrets.redisUrl` | `REDIS_URL` | Shared across replicas |
| `secrets.dataEncryptionKey` | `DATA_ENCRYPTION_KEY` | Min 32 chars; also accepts `mfaEncryptionKey` |
| `secrets.jwtPublicKeyPem` | `JWT_PUBLIC_KEY_PEM` | Required in production |
| `secrets.jwtPrivateKeyPem` | `JWT_PRIVATE_KEY_PEM` | Or use `env.JWT_KMS_HTTP_URL` |
| `secrets.metricsBearerToken` | `METRICS_BEARER_TOKEN` | Required in production |
| `secrets.databaseMigratorUrl` | `DATABASE_MIGRATOR_URL` | Audit retention / migrations |

## Optional configuration

| Value key | Env var | Purpose |
|-----------|---------|---------|
| `env.JWT_KMS_HTTP_URL` | Remote JWT signing |
| `env.JWT_KMS_KEY_ID` | Key id for JWT KMS |
| `env.KMS_HTTP_URL` | External KMS for data encryption |
| `env.OTEL_ENDPOINT` | OpenTelemetry collector (gRPC) |
| `env.AUDIT_EXPORT_WEBHOOK` | SIEM webhook for audit events |
| `env.ALLOWED_ORIGINS` | CORS origins (comma-separated) |
| `env.DATABASE_READ_URL` | Read replica for login lookups |
| `env.WEBAUTHN_RP_ID` | WebAuthn relying party id |
| `env.AUDIT_RETENTION_DAYS` | Audit event purge retention (default 365) |
| `env.DSAR_ARTIFACT_RETENTION_DAYS` | DSAR export retention (default 30) |

## Scaling and HA

- Default: 3 replicas with HPA (3–10) and PDB `minAvailable: 2`
- Migrations run once via init container (`migration.enabled`)
- Archival purge runs on a single leader pod via Redis lease (`archival:leader`, 55s TTL)

## Local Kubernetes (kind)

See `deploy/kind/README.md` for a single-node perf setup with `deploy/kind/values-local.yaml`.
