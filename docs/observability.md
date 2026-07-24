# Observability

## Logging

Set `RUST_LOG` to control log verbosity:

```bash
RUST_LOG=authsvc_server=info,tower_http=info
```

Structured logs use `tracing`. In production, ship stdout to your log aggregator (CloudWatch, Loki, Datadog, etc.).

## Distributed tracing

Enable OpenTelemetry export by setting `OTEL_ENDPOINT` to your collector gRPC endpoint:

```bash
OTEL_ENDPOINT=http://otel-collector:4317
```

The server initializes a `tracing-opentelemetry` layer at startup (`observability::init_tracing`). Spans cover HTTP requests and key auth flows.

Helm: set `env.OTEL_ENDPOINT` in `values.yaml`.

## Health checks

| Endpoint | Purpose |
|----------|---------|
| `GET /health` | Liveness (process up) |
| `GET /ready` | Readiness (Postgres + Redis reachable) |

Kubernetes probes are configured in `deploy/helm/authsvc/values.yaml`.

## Audit export

Forward audit events to a SIEM or webhook:

```bash
AUDIT_EXPORT_WEBHOOK=https://siem.example.com/ingest/authsvc
```

Each `audit()` call POSTs a JSON payload asynchronously. Failures are logged but do not block the request.

## Metrics

Use your tracing backend or scrape ingress/service metrics (request rate, latency, 5xx). For load testing, see `scripts/perf_test.sh` and `make perf`.

## Retention jobs

Background archival (leader-elected) purges expired OTP codes, old refresh tokens, audit events past `AUDIT_RETENTION_DAYS`, and completed DSAR exports past `DSAR_ARTIFACT_RETENTION_DAYS`. Monitor archival logs for `archival job completed` and `archival job failed`.
