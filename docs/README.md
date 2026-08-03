# Documentation

## Getting started

- [README](../README.md) — quick start and feature overview
- [`.env.example`](../.env.example) — configuration reference
- [OpenAPI spec](../api/openapi.yaml) — HTTP API contract

## Deployment

- [operator-day1.md](operator-day1.md) — end-to-end day-1 production checklist
- [deploy-production.md](deploy-production.md) — production secrets, DB roles, JWT keys
- [helm-deployment.md](helm-deployment.md) — Kubernetes / Helm guide (`values-prod.yaml`, `verify_production.sh`)
- [observability.md](observability.md) — Prometheus metrics and OpenTelemetry

## Authentication & federation

- [SAML.md](SAML.md) — SAML 2.0 SP and IdP setup

## Security & compliance

- [security-whitepaper.md](security-whitepaper.md) — architecture and security controls
- [security-assessment-checklist.md](security-assessment-checklist.md) — pre-audit self-assessment
- [soc2-control-mapping.md](soc2-control-mapping.md) — control mapping reference
- [SECURITY.md](../SECURITY.md) — vulnerability reporting

## Runbooks

- [runbooks/key-compromise.md](runbooks/key-compromise.md) — JWT signing key compromise
- [runbooks/account-lockdown.md](runbooks/account-lockdown.md) — account lockdown procedures
- [runbooks/data-breach.md](runbooks/data-breach.md) — data breach response
- [runbooks/notifications-production.md](runbooks/notifications-production.md) — email/SMS production setup
- [runbooks/disaster-recovery.md](runbooks/disaster-recovery.md) — backup, restore, and failover

## Performance

- [performance.md](performance.md) — benchmarks and tuning

## Contributing

- [CONTRIBUTING.md](../CONTRIBUTING.md) — development setup and PR guidelines
- [CODE_OF_CONDUCT.md](../CODE_OF_CONDUCT.md) — community standards
- [CHANGELOG.md](../CHANGELOG.md) — release history
