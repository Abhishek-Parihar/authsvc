# Local Kubernetes (kind)

Lightweight single-node cluster for perf testing authsvc with Postgres and Redis.

## Prerequisites

- [Colima](https://github.com/abiosoft/colima) or Docker Desktop
- `kind`, `kubectl`, `helm`, `hey`

```bash
brew install kind kubectl helm hey
colima start
```

## Deploy

```bash
export DOCKER_HOST=unix://$HOME/.colima/default/docker.sock
./scripts/k8s_local_up.sh
```

This creates cluster `authsvc`, builds the `authsvc:local` image, installs Postgres/Redis/metrics-server, and deploys via Helm.

**Endpoint:** http://127.0.0.1:18080 (NodePort 30080 → kind control-plane)

## Performance test (latency + CPU/RAM)

```bash
export DOCKER_HOST=unix://$HOME/.colima/default/docker.sock
DURATION=10s CONCURRENCY=50 CONCURRENCY_CPU_HEAVY=15 ./scripts/k8s_perf_test.sh
```

Outputs:
- `hey` latency/RPS per endpoint
- `kubectl top` summary (avg/max CPU cores and memory MiB per pod)
- Prometheus counters from `/metrics`

## Teardown

```bash
./scripts/k8s_local_down.sh
```
