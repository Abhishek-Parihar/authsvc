#!/usr/bin/env bash
# Performance test against authsvc running in local kind; includes CPU/RAM sampling.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

CLUSTER_NAME="${CLUSTER_NAME:-authsvc}"
KUBE_CONTEXT="kind-${CLUSTER_NAME}"
export DOCKER_HOST="${DOCKER_HOST:-unix://${HOME}/.colima/default/docker.sock}"

kubectl config use-context "$KUBE_CONTEXT" >/dev/null 2>&1 || true

BASE_URL="${BASE_URL:-http://127.0.0.1:18080}"
DURATION="${DURATION:-10s}"
CONCURRENCY="${CONCURRENCY:-50}"
CONCURRENCY_CPU_HEAVY="${CONCURRENCY_CPU_HEAVY:-15}"
DURATION_CPU_HEAVY="${DURATION_CPU_HEAVY:-10s}"
BOOTSTRAP_SECRET="${BOOTSTRAP_SECRET:-perf-bootstrap-k8s}"
RESOURCE_LOG="${RESOURCE_LOG:-/tmp/authsvc-k8s-resources.csv}"
RESOURCE_SUMMARY="${RESOURCE_SUMMARY:-/tmp/authsvc-k8s-resources-summary.txt}"

if ! kubectl --context "$KUBE_CONTEXT" get deployment authsvc -n authsvc >/dev/null 2>&1; then
  echo "==> Cluster not ready; running k8s_local_up.sh"
  "$ROOT/scripts/k8s_local_up.sh"
fi

monitor_resources() {
  local stop_file="$1"
  if [[ ! -s "$RESOURCE_LOG" ]]; then
    echo "timestamp,pod,cpu_cores,memory_mib" >"$RESOURCE_LOG"
  fi
  while [[ ! -f "$stop_file" ]]; do
    local samples
    samples=$(kubectl top pods -n authsvc --no-headers 2>/dev/null || true)
    if [[ -n "$samples" ]]; then
      while read -r pod cpu mem _rest; do
        [[ -z "$pod" ]] && continue
        cpu_val="${cpu%m}"
        if [[ "$mem" == *Gi ]]; then
          mem_val=$(python3 -c "print(round(float('${mem%Gi}')*1024, 1))")
        elif [[ "$mem" == *Mi ]]; then
          mem_val="${mem%Mi}"
        elif [[ "$mem" == *Ki ]]; then
          mem_val=$(python3 -c "print(round(float('${mem%Ki}')/1024, 1))")
        else
          mem_val="$mem"
        fi
        echo "$(date +%s),$pod,$cpu_val,$mem_val" >>"$RESOURCE_LOG"
      done <<<"$samples"
    fi
    sleep 1
  done
}

summarize_resources() {
  RESOURCE_LOG="$RESOURCE_LOG" python3 - <<'PY' >"$RESOURCE_SUMMARY"
import csv
import os
from collections import defaultdict

path = os.environ.get("RESOURCE_LOG", "/tmp/authsvc-k8s-resources.csv")
stats = defaultdict(lambda: {"cpu": [], "mem": []})

try:
    with open(path) as f:
        reader = csv.DictReader(f)
        for row in reader:
            pod = row["pod"]
            try:
                stats[pod]["cpu"].append(float(row["cpu_cores"]))
                stats[pod]["mem"].append(float(row["memory_mib"]))
            except ValueError:
                pass
except FileNotFoundError:
    print("No resource samples collected")
    raise SystemExit(0)

print("=== Resource usage (kubectl top samples during load) ===\n")
print(f"{'Pod':<40} {'CPU avg':>10} {'CPU max':>10} {'RAM avg':>12} {'RAM max':>12}")
print("-" * 86)
for pod in sorted(stats):
    cpu = stats[pod]["cpu"]
    mem = stats[pod]["mem"]
    if not cpu:
        continue
    print(
        f"{pod:<40} "
        f"{sum(cpu)/len(cpu):>9.3f}c "
        f"{max(cpu):>9.3f}c "
        f"{sum(mem)/len(mem):>10.1f}Mi "
        f"{max(mem):>10.1f}Mi"
    )
PY
  cat "$RESOURCE_SUMMARY"
}

MONITOR_PID=""
STOP_FILE=""

start_monitor() {
  STOP_FILE=$(mktemp)
  monitor_resources "$STOP_FILE" &
  MONITOR_PID=$!
}

stop_monitor() {
  local stop_file="$1"
  touch "$stop_file"
  if [[ -n "${MONITOR_PID:-}" ]]; then
    wait "$MONITOR_PID" 2>/dev/null || true
    MONITOR_PID=""
  fi
  rm -f "$stop_file"
}

run_load() {
  local name="$1"
  local url="$2"
  local method="${3:-GET}"
  local body="${4:-}"
  local auth_header="${5:-}"
  local workers="${6:-$CONCURRENCY}"
  local duration="${7:-$DURATION}"

  echo ""
  echo "=== $name ==="

  start_monitor
  local stop_file="$STOP_FILE"

  if command -v hey >/dev/null 2>&1; then
    if [[ "$method" == "POST" && -n "$body" ]]; then
      if [[ -n "$auth_header" ]]; then
        hey -z "$duration" -c "$workers" -m POST \
          -H 'Content-Type: application/json' \
          -H "Authorization: $auth_header" \
          -d "$body" \
          "$url"
      else
        hey -z "$duration" -c "$workers" -m POST \
          -H 'Content-Type: application/json' \
          -d "$body" \
          "$url"
      fi
    elif [[ -n "$auth_header" ]]; then
      hey -z "$duration" -c "$workers" -H "Authorization: $auth_header" "$url"
    else
      hey -z "$duration" -c "$workers" "$url"
    fi
  else
    echo "hey is required for k8s perf test"
    stop_monitor "$stop_file"
    exit 1
  fi

  stop_monitor "$stop_file"
}

echo "==> K8s perf test target: $BASE_URL"
echo "==> Cluster: kind-${CLUSTER_NAME}"

for i in $(seq 1 60); do
  if curl -sf "$BASE_URL/health" >/dev/null; then
    break
  fi
  sleep 1
done

curl -sf "$BASE_URL/health" >/dev/null || {
  echo "authsvc not reachable at $BASE_URL"
  kubectl get pods -n authsvc
  kubectl logs -n authsvc -l app.kubernetes.io/name=authsvc --tail=40 || true
  exit 1
}

echo "==> Baseline pod resources"
kubectl top pods -n authsvc 2>/dev/null || true

echo "==> Seeding test user + client"
EMAIL="k8s-perf-$(date +%s)@example.com"
curl -sf -X POST "$BASE_URL/v1/auth/register" \
  -H "Authorization: Bearer $BOOTSTRAP_SECRET" \
  -H 'Content-Type: application/json' \
  -d "{\"email\":\"$EMAIL\",\"password\":\"perf-password-123\"}" >/dev/null

CLIENT_JSON=$(curl -sf -X POST "$BASE_URL/v1/clients" \
  -H "Authorization: Bearer $BOOTSTRAP_SECRET" \
  -H 'Content-Type: application/json' \
  -d '{"name":"k8s-perf-client","redirect_uris":["http://localhost/callback"]}')

CLIENT_ID=$(echo "$CLIENT_JSON" | python3 -c 'import json,sys; print(json.load(sys.stdin)["client_id"])')
CLIENT_SECRET=$(echo "$CLIENT_JSON" | python3 -c 'import json,sys; print(json.load(sys.stdin)["client_secret"])')

TOKEN_JSON=$(curl -sf -X POST "$BASE_URL/oauth/token" \
  -H 'Content-Type: application/json' \
  -d "{\"grant_type\":\"password\",\"client_id\":\"$CLIENT_ID\",\"client_secret\":\"$CLIENT_SECRET\",\"username\":\"$EMAIL\",\"password\":\"perf-password-123\"}")

ACCESS_TOKEN=$(echo "$TOKEN_JSON" | python3 -c 'import json,sys; print(json.load(sys.stdin)["access_token"])')

: >"$RESOURCE_LOG"
run_load "Health (liveness)" "$BASE_URL/health"
run_load "JWKS" "$BASE_URL/.well-known/jwks.json"
run_load "Token (password grant)" "$BASE_URL/oauth/token" POST \
  "{\"grant_type\":\"password\",\"client_id\":\"$CLIENT_ID\",\"client_secret\":\"$CLIENT_SECRET\",\"username\":\"$EMAIL\",\"password\":\"perf-password-123\"}" \
  "" "$CONCURRENCY_CPU_HEAVY" "$DURATION_CPU_HEAVY"
run_load "Userinfo (Bearer)" "$BASE_URL/oauth/userinfo" GET "" "Bearer $ACCESS_TOKEN"

echo ""
summarize_resources

echo ""
echo "=== Post-test pod resources ==="
kubectl top pods -n authsvc 2>/dev/null || true

echo ""
echo "=== Prometheus metrics (authsvc) ==="
curl -sf "$BASE_URL/metrics" | rg 'authsvc_' | head -20 || true

echo ""
echo "Raw samples: $RESOURCE_LOG"
echo "Summary:    $RESOURCE_SUMMARY"
echo "K8s perf test complete."
