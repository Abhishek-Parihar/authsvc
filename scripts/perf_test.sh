#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PORT="${PORT:-18080}"
BASE_URL="http://127.0.0.1:${PORT}"
DURATION="${DURATION:-15s}"
CONCURRENCY="${CONCURRENCY:-50}"
REQUESTS="${REQUESTS:-5000}"

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

run_load() {
  local name="$1"
  local url="$2"
  local method="${3:-GET}"
  local body="${4:-}"
  local auth_header="${5:-}"

  echo ""
  echo "=== $name ==="

  if command -v hey >/dev/null 2>&1; then
    if [[ "$method" == "POST" && -n "$body" ]]; then
      if [[ -n "$auth_header" ]]; then
        hey -z "$DURATION" -c "$CONCURRENCY" -m POST \
          -H 'Content-Type: application/json' \
          -H "Authorization: $auth_header" \
          -d "$body" \
          "$url"
      else
        hey -z "$DURATION" -c "$CONCURRENCY" -m POST \
          -H 'Content-Type: application/json' \
          -d "$body" \
          "$url"
      fi
    elif [[ -n "$auth_header" ]]; then
      hey -z "$DURATION" -c "$CONCURRENCY" -H "Authorization: $auth_header" "$url"
    else
      hey -z "$DURATION" -c "$CONCURRENCY" "$url"
    fi
  else
    echo "(hey not installed — using curl loop fallback)"
    local ok=0 fail=0 start=$(date +%s)
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
    local end=$(date +%s)
    local elapsed=$((end-start))
    [[ "$elapsed" -lt 1 ]] && elapsed=1
    echo "requests=$REQUESTS ok=$ok fail=$fail elapsed=${elapsed}s rps=$((REQUESTS/elapsed))"
  fi
}

run_load "Health (liveness)" "$BASE_URL/health"
run_load "JWKS" "$BASE_URL/.well-known/jwks.json"
run_load "Token (password grant)" "$BASE_URL/oauth/token" POST \
  "{\"grant_type\":\"password\",\"client_id\":\"$CLIENT_ID\",\"client_secret\":\"$CLIENT_SECRET\",\"username\":\"$EMAIL\",\"password\":\"perf-password-123\"}"
run_load "Userinfo (authenticated)" "$BASE_URL/oauth/userinfo" GET "" "Bearer $ACCESS_TOKEN"

echo ""
echo "=== Prometheus metrics snapshot ==="
curl -sf "$BASE_URL/metrics" | rg 'authsvc_' | head -20 || true

echo ""
echo "Perf test complete. Server log: /tmp/authsvc-perf.log"
