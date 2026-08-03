# Disaster recovery runbook

Targets for self-hosted authsvc. Adjust RTO/RPO to your SLA.

| Metric | Target |
|--------|--------|
| RTO (restore service) | 4 hours |
| RPO (data loss window) | 15 minutes (managed Postgres PITR) |

## Components

| Component | Critical data | Backup strategy |
|-----------|---------------|-----------------|
| PostgreSQL | Users, clients, keys, audit, RBAC | Managed PITR + daily snapshots |
| Redis | Sessions, rate limits, MFA challenges | Ephemeral OK; use Redis persistence (AOF) if sessions must survive restart |
| JWT signing keys | `signing_keys`, env PEM/KMS | DB backup + separate KMS/key vault |
| `DATA_ENCRYPTION_KEY` | MFA secrets, webhooks | External secret manager; never only in DB |

## Postgres backup (recommended)

1. Enable **continuous backup / PITR** on managed Postgres (RDS, Cloud SQL, etc.).
2. Retain snapshots ≥ 30 days; test restore quarterly.
3. Application role `authsvc_app` cannot delete `audit_events`; restores use migrator/superuser.

### Restore drill

```bash
# 1. Restore Postgres to new instance or point-in-time
# 2. Update DATABASE_URL / DATABASE_MIGRATOR_URL secrets
# 3. Roll deployment (no schema migration if PITR to same schema version)
kubectl rollout restart deployment/authsvc -n authsvc

# 4. Verify
export AUTHSVC_URL=https://auth.example.com
export EXPECTED_ISSUER=https://auth.example.com
export METRICS_BEARER_TOKEN=...
make verify-production
```

## Redis

- **Sessions / rate limits**: Acceptable to lose on full Redis failure; users re-authenticate.
- **Production**: Use managed Redis with AOF or RDB if you require session continuity across Redis restart.
- After Redis loss: no Postgres restore required; pods reconnect automatically.

## JWT key compromise + rotation

See [key-compromise.md](./key-compromise.md). After rotation:

```bash
curl -X POST "$AUTHSVC_URL/v1/keys/rotate" \
  -H "Authorization: Bearer $ADMIN_ACCESS_TOKEN"
```

Verify JWKS shows old key in grace period, then only new key after `JWT_KEY_GRACE_SECS`.

## Signing key age policy

- `JWT_KEY_MAX_AGE_DAYS` (default 90) triggers compliance alert and metric `authsvc_jwt_key_age_alerts_total`.
- Check `/v1/compliance/status` for `jwt_key_rotation_due`.
- Rotate before max age in normal operations.

## Multi-region / failover

authsvc is single-region by default. For DR:

1. Standby Postgres replica in second region (read replica or cross-region replica).
2. Promote replica + update `DATABASE_URL` in failover region.
3. Deploy authsvc with same `ISSUER` (global DNS) or update issuer + client configs.
4. Redis is not replicated cross-region by default; expect session logout on failover.

## Post-incident

1. Run `verify_production.sh`.
2. Review audit events for suspicious activity (`/v1/audit/events`).
3. Document timeline in incident tracker; update this runbook if gaps found.

## Related

- [key-compromise.md](./key-compromise.md)
- [data-breach.md](./data-breach.md)
- [../deploy-production.md](../deploy-production.md)
