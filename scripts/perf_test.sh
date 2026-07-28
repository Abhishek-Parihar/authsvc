#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PORT="${PORT:-18080}"
BASE_URL="http://127.0.0.1:${PORT}"
DURATION="${DURATION:-15s}"
CONCURRENCY="${CONCURRENCY:-50}"
REQUESTS="${REQUESTS:-5000}"
ENFORCE_SLO="${ENFORCE_SLO:-0}"
SLO_MODE="${SLO_MODE:-local}"

# Minimum RPS per endpoint (local = dev hardware, ci = GitHub Actions)
declare -A SLO_RPS
if [[ "$SLO_MODE" == "ci" ]]; then
  SLO_RPS=(
    ["Health (liveness)"]=500
    ["JWKS"]=200
    ["Token (password grant)"]=30
    ["Token (refresh grant)"]=50
    ["Authz check"]=100
    ["Userinfo (authenticated)"]=50
  )
  declare -A SLO_P99_MS
  SLO_P99_MS=(
    ["Health (liveness)"]=50
    ["JWKS"]=100
    ["Token (password grant)"]=2000
    ["Token (refresh grant)"]=1000
    ["Authz check"]=200
    ["Userinfo (authenticated)"]=300
  )
else
  SLO_RPS=(
    ["Health (liveness)"]=2000
    ["JWKS"]=1000
    ["Token (password grant)"]=100
    ["Token (refresh grant)"]=200
    ["Authz check"]=500
    ["Userinfo (authenticated)"]=300
  )
  declare -A SLO_P99_MS
  SLO_P99_MS=(
    ["Health (liveness)"]=10
    ["JWKS"]=15
    ["Token (password grant)"]=500
    ["Token (refresh grant)"]=200
    ["Authz check"]=50
    ["Userinfo (authenticated)"]=30
  )
fi

SLO_FAILURES=0

echo "==> Starting Postgres + Redis (Homebrew)"
"$ROOT/scripts/brew_services.sh" up

export DATABASE_URL="${DATABASE_URL:-postgres://authsvc:authsvc@127.0.0.1:5432/authsvc}"
export REDIS_URL="${REDIS_URL:-redis://127.0.0.1:6379}"
export ISSUER="${ISSUER:-$BASE_URL}"
export HOST="127.0.0.1"
export PORT
export BOOTSTRAP_SECRET="${BOOTSTRAP_SECRET:-perf-bootstrap}"
export RATE_LIMIT_PER_MINUTE="${RATE_LIMIT_PER_MINUTE:-100000}"

echo "==> Building authsvc"
cargo build --release -p authsvc-server

echo "==> Starting authsvc on $BASE_URL"
./target/release/authsvc > /tmp/authsvc-perf.log 2>&1 &
SERVER_PID=$!
trap 'kill $SERVER_PID 2>/dev/null || true' EXIT

for i in $(seq 1 30); do
  if curl -sf "$BASE_URL/health" >/dev/null; then
    break
  fi
  sleep 1
done

curl -sf "$BASE_URL/health" >/dev/null || {
  echo "authsvc failed to start; log:"
  tail -50 /tmp/authsvc-perf.log
  exit 1
}

echo "==> Seeding test user + client"
EMAIL="perf-$(date +%s)@example.com"
curl -sf -X POST "$BASE_URL/v1/auth/register" \
  -H "Authorization: Bearer $BOOTSTRAP_SECRET" \
  -H 'Content-Type: application/json' \
  -d "{\"email\":\"$EMAIL\",\"password\":\"perf-password-123\"}" >/dev/null

CLIENT_JSON=$(curl -sf -X POST "$BASE_URL/v1/clients" \
  -H "Authorization: Bearer $BOOTSTRAP_SECRET" \
  -H 'Content-Type: application/json' \
  -d '{"name":"perf-client","redirect_uris":["http://localhost/callback"]}')

CLIENT_ID=$(echo "$CLIENT_JSON" | python3 -c 'import json,sys; print(json.load(sys.stdin)["client_id"])')
CLIENT_SECRET=$(echo "$CLIENT_JSON" | python3 -c 'import json,sys; print(json.load(sys.stdin)["client_secret"])')

TOKEN_JSON=$(curl -sf -X POST "$BASE_URL/oauth/token" \
  -H 'Content-Type: application/json' \
  -d "{\"grant_type\":\"password\",\"client_id\":\"$CLIENT_ID\",\"client_secret\":\"$CLIENT_SECRET\",\"username\":\"$EMAIL\",\"password\":\"perf-password-123\"}")

ACCESS_TOKEN=$(echo "$TOKEN_JSON" | python3 -c 'import json,sys; print(json.load(sys.stdin)["access_token"])')
REFRESH_TOKEN=$(echo "$TOKEN_JSON" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("refresh_token",""))')
USER_ID=$(echo "$ACCESS_TOKEN" | python3 -c 'import sys,base64,json; p=sys.stdin.read().strip().split(".")[1]; p+="="*((4-len(p)%4)%4); print(json.loads(base64.urlsafe_b64decode(p))["sub"])')
ACCOUNT_ID=$(echo "$ACCESS_TOKEN" | python3 -c 'import sys,base64,json; p=sys.stdin.read().strip().split(".")[1]; p+="="*((4-len(p)%4)%4); print(json.loads(base64.urlsafe_b64decode(p))["account_id"])')

check_slo_latency() {
  local name="$1"
  local p99_ms="$2"
  local max="${SLO_P99_MS[$name]:-0}"
  if [[ "$max" -eq 0 ]] || [[ -z "$p99_ms" ]] || [[ "$p99_ms" == "0" ]]; then
    return
  fi
  if python3 -c "import sys; sys.exit(0 if float('$p99_ms') <= $max else 1)"; then
    echo "  p99 OK: ${p99_ms}ms <= ${max}ms"
  else
    echo "  p99 FAIL: ${p99_ms}ms > ${max}ms"
    SLO_FAILURES=$((SLO_FAILURES + 1))
  fi
}

check_slo() {
  local name="$1"
  local rps="$2"
  local min="${SLO_RPS[$name]:-0}"
  if [[ "$min" -eq 0 ]]; then
    return
  fi
  if python3 -c "import sys; sys.exit(0 if float('$rps') >= $min else 1)"; then
    echo "  SLO OK: ${rps} RPS >= ${min} (target)"
  else
    echo "  SLO FAIL: ${rps} RPS < ${min} (target)"
    SLO_FAILURES=$((SLO_FAILURES + 1))
  fi
}

run_load() {
  local name="$1"
  local url="$2"
  local method="${3:-GET}"
  local body="${4:-}"
  local auth_header="${5:-}"

  echo ""
  echo "=== $name ==="

  local measured_rps="0"

  if command -v hey >/dev/null 2>&1; then
    local hey_out
    if [[ "$method" == "POST" && -n "$body" ]]; then
      if [[ -n "$auth_header" ]]; then
        hey_out=$(hey -z "$DURATION" -c "$CONCURRENCY" -m POST \
          -H 'Content-Type: application/json' \
          -H "Authorization: $auth_header" \
          -d "$body" \
          "$url" 2>&1) || true
      else
        hey_out=$(hey -z "$DURATION" -c "$CONCURRENCY" -m POST \
          -H 'Content-Type: application/json' \
          -d "$body" \
          "$url" 2>&1) || true
      fi
    elif [[ -n "$auth_header" ]]; then
      hey_out=$(hey -z "$DURATION" -c "$CONCURRENCY" -H "Authorization: $auth_header" "$url" 2>&1) || true
    else
      hey_out=$(hey -z "$DURATION" -c "$CONCURRENCY" "$url" 2>&1) || true
    fi
    echo "$hey_out"
    measured_rps=$(echo "$hey_out" | awk '/Requests\/sec:/ {print $2; exit}')
    [[ -z "$measured_rps" ]] && measured_rps="0"
    local p99_sec
    p99_sec=$(echo "$hey_out" | awk '/99%/ {print $(NF-1); exit}')
    if [[ -n "$p99_sec" ]]; then
      local p99_ms
      p99_ms=$(python3 -c "print(round(float('$p99_sec') * 1000, 2))")
      check_slo_latency "$name" "$p99_ms"
    fi
  else
    echo "(hey not installed — using curl loop fallback)"
    local ok=0 fail=0 start end elapsed
    start=$(date +%s%N)
    for ((i=0; i<REQUESTS; i++)); do
      if [[ "$method" == "POST" ]]; then
        if curl -sf -X POST -H 'Content-Type: application/json' -d "$body" "$url" >/dev/null; then
          ok=$((ok+1))
        else
          fail=$((fail+1))
        fi
      elif [[ -n "$auth_header" ]]; then
        if curl -sf -H "Authorization: $auth_header" "$url" >/dev/null; then
          ok=$((ok+1))
        else
          fail=$((fail+1))
        fi
      else
        if curl -sf "$url" >/dev/null; then
          ok=$((ok+1))
        else
          fail=$((fail+1))
        fi
      fi
    done
    end=$(date +%s%N)
    elapsed=$(( (end - start) / 1000000 ))
    [[ "$elapsed" -lt 1 ]] && elapsed=1000
    measured_rps=$(python3 -c "print(round($REQUESTS / ($elapsed / 1000), 2))")
    echo "requests=$REQUESTS ok=$ok fail=$fail elapsed_ms=${elapsed} rps=${measured_rps}"
  fi

  check_slo "$name" "$measured_rps"
}

run_load "Health (liveness)" "$BASE_URL/health"
run_load "JWKS" "$BASE_URL/.well-known/jwks.json"
run_load "Token (password grant)" "$BASE_URL/oauth/token" POST \
  "{\"grant_type\":\"password\",\"client_id\":\"$CLIENT_ID\",\"client_secret\":\"$CLIENT_SECRET\",\"username\":\"$EMAIL\",\"password\":\"perf-password-123\"}"
run_load "Token (refresh grant)" "$BASE_URL/oauth/token" POST \
  "{\"grant_type\":\"refresh_token\",\"client_id\":\"$CLIENT_ID\",\"client_secret\":\"$CLIENT_SECRET\",\"refresh_token\":\"$REFRESH_TOKEN\"}"
run_load "Authz check" "$BASE_URL/v1/authz/check" POST \
  "{\"subject\":\"user:$USER_ID\",\"resource\":\"users\",\"action\":\"read\",\"account_id\":\"$ACCOUNT_ID\"}"
run_load "Userinfo (authenticated)" "$BASE_URL/oauth/userinfo" GET "" "Bearer $ACCESS_TOKEN"

echo ""
echo "=== SLO summary (mode=$SLO_MODE, enforce=$ENFORCE_SLO) ==="
if [[ "$SLO_FAILURES" -gt 0 ]]; then
  echo "FAILED: $SLO_FAILURES endpoint(s) below minimum RPS"
  if [[ "$ENFORCE_SLO" == "1" ]]; then
    exit 1
  fi
else
  echo "PASSED: all endpoints met minimum RPS targets"
fi

echo ""
echo "=== Prometheus metrics snapshot ==="
curl -sf "$BASE_URL/metrics" | rg 'authsvc_' | head -20 || true

echo ""
echo "Perf test complete. Server log: /tmp/authsvc-perf.log"
