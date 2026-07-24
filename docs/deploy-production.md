# Production deployment guide

## Database roles

Run migrations before starting the application. Migration `016_audit_append_only` creates the `authsvc_app` role with append-only access to `audit_events`.

### Recommended setup

1. **Migrator user** (superuser or owner): runs `sqlx migrate` / Helm init container.
2. **Application user** (`authsvc_app`): used by `DATABASE_URL` in production.

```sql
-- After migrations
GRANT USAGE ON SCHEMA public TO authsvc_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO authsvc_app;
REVOKE UPDATE, DELETE ON audit_events FROM authsvc_app;
```

Use a dedicated password for `authsvc_app` and rotate regularly.

## JWT signing keys

**Never store plaintext private keys in Postgres.**

Production options (in order of preference):

1. **`JWT_PRIVATE_KEY_PEM` + `JWT_PUBLIC_KEY_PEM` env vars** — private key never touches the database.
2. **`JWT_KMS_HTTP_URL`** — remote signing via `POST /sign` with `{ "message": "<base64>", "key_id": "...", "algorithm": "RSASSA_PKCS1_V1_5_SHA_256" }`; only the public key is stored locally.
3. **Encrypted at rest** — rotation via `POST /v1/keys/rotate` stores `encrypted_private_pem` (AES-256-GCM via `DATA_ENCRYPTION_KEY`).

## Secrets

| Variable | Required (prod) | Purpose |
|----------|-----------------|---------|
| `DATA_ENCRYPTION_KEY` | Yes | MFA, webhooks, IdP configs, encrypted JWT keys |
| `METRICS_BEARER_TOKEN` | Yes | Protects `/metrics` in production |
| `DATABASE_MIGRATOR_URL` | Recommended | Superuser/migrator connection for audit retention purge |
| `MIGRATE_ON_START` | No | Set `false` when migrations run via init container (Helm default) |
| `JWT_PRIVATE_KEY_PEM` | Yes* | JWT signing (*or use `JWT_KMS_HTTP_URL`) |
| `JWT_KMS_HTTP_URL` | No | Remote JWT signing endpoint |
| `JWT_KMS_KEY_ID` | No | Key identifier for remote JWT signing |
| `JWT_PUBLIC_KEY_PEM` | Yes | JWKS publication |
| `DISABLE_PASSWORD_GRANT` | Auto `true` when `ENV=production` | Disable resource-owner password grant |

## Audit immutability

- Application role `authsvc_app` cannot `UPDATE` or `DELETE` `audit_events`.
- Retention/archival jobs must use the migrator/superuser role.
- Optional: forward all audit events to SIEM via `AUDIT_EXPORT_WEBHOOK`.

## Horizontal scaling

- Helm default: 3 replicas, HPA, PDB `minAvailable: 2`
- Run migrations via init container (`MIGRATE_ONLY=true` on the app image); set `MIGRATE_ON_START=false` on app pods
- Use `DATABASE_MIGRATOR_URL` for the archival job when the app role cannot delete audit rows
- Use managed Redis; configure `DATABASE_MAX_CONNECTIONS` per pod
- Optional read replica: `DATABASE_READ_URL` (login lookups)

## Row-level security

Migrations enable RLS on `account_members` and `audit_events`. The server sets `app.account_id` from the JWT on each authenticated request.
