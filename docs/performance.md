# Performance baselines

Single-node benchmarks using `scripts/perf_test.sh` on developer hardware (Apple Silicon / 8+ cores, local Postgres + Redis via Homebrew).

## SLO targets

| Endpoint | Target RPS | p99 latency |
|----------|------------|-------------|
| `GET /health` | > 2,000 | < 10 ms |
| `GET /.well-known/jwks.json` | > 1,000 | < 15 ms |
| `POST /oauth/token` (password) | > 100 | < 500 ms |
| `POST /oauth/token` (refresh) | > 200 | < 200 ms |
| `POST /v1/authz/check` | > 500 | < 50 ms |
| `GET /oauth/userinfo` | > 300 | < 30 ms |

## Running locally

```bash
make perf
# or
./scripts/perf_test.sh
```

Environment variables:

- `DURATION` — load test duration per endpoint (default `15s`)
- `CONCURRENCY` — concurrent workers (default `50`)
- `PORT` — server port (default `18080`)

## CI regression guard

The nightly workflow (`.github/workflows/nightly-perf.yml`) runs a shortened perf smoke test with **SLO enforcement** (`ENFORCE_SLO=1`, `SLO_MODE=ci`). The job fails if any endpoint drops below CI minimum RPS.

Local enforcement:

```bash
ENFORCE_SLO=1 ./scripts/perf_test.sh
```

Environment variables:

- `ENFORCE_SLO` — exit non-zero on SLO breach (default `0`)
- `SLO_MODE` — `local` (dev hardware targets) or `ci` (GitHub Actions targets)

Nightly CI installs `hey` and enforces both minimum RPS and p99 latency per endpoint.

## Tuning

- Increase `DATABASE_MAX_CONNECTIONS` for high concurrency.
- Use `DATABASE_READ_URL` for read-heavy authz checks.
- Enable Redis permission cache (default 60s TTL) for repeated authz on the same subject.
