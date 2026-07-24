# Database migrations

SQL migrations live in this directory and are applied automatically at server startup via `sqlx::migrate!`.

## Policy

- **Forward-only in production** — never run `.down.sql` against production data.
- **Numbered sequentially** — use the next integer (`020_`, `021_`, …).
- **RLS changes** — tenant-scoped tables must set `app.account_id` inside a transaction (`SET LOCAL`) before DML; auth lookup tables (`api_keys`, `scim_tokens`) are exempt from FORCE RLS (see `020_rls_auth_tables`).
- **Roles** — run migrations as a superuser; the application connects as `authsvc_app` (see `016_audit_append_only`).

## Local development

```bash
export DATABASE_URL=postgres://authsvc:authsvc@127.0.0.1:5432/authsvc
sqlx migrate run --source migrations
```

## Rollback (dev only)

```bash
sqlx migrate revert --source migrations
```
