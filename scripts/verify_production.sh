#!/usr/bin/env bash
# Post-deploy smoke checks for production authsvc.
#
# Usage:
#   export AUTHSVC_URL=https://auth.example.com
#   export EXPECTED_ISSUER=https://auth.example.com   # optional
#   export METRICS_BEARER_TOKEN=...                 # optional
#   export ADMIN_ACCESS_TOKEN=...                   # optional admin JWT for compliance checks
#   ./scripts/verify_production.sh
#
set -euo pipefail

BASE_URL="${AUTHSVC_URL:-}"
EXPECTED_ISSUER="${EXPECTED_ISSUER:-}"
METRICS_TOKEN="${METRICS_BEARER_TOKEN:-}"
ADMIN_TOKEN="${ADMIN_ACCESS_TOKEN:-}"

if [[ -z "$BASE_URL" ]]; then
  echo "error: set AUTHSVC_URL (e.g. https://auth.example.com)" >&2
  exit 1
fi

BASE_URL="${BASE_URL%/}"

if ! command -v curl >/dev/null 2>&1; then
  echo "error: curl is required" >&2
  exit 1
fi
if ! command -v jq >/dev/null 2>&1; then
  echo "error: jq is required" >&2
  exit 1
fi

failures=0

ok() {
  echo "OK  $*"
}

fail() {
  echo "FAIL $*"
  failures=$((failures + 1))
}

http_code() {
  curl -s -o /dev/null -w '%{http_code}' "$@"
}

header_value() {
  curl -s -D - -o /dev/null "$@" | awk -F': ' 'tolower($1)=="'"$1"'"{print $2; exit}' | tr -d '\r'
}

echo "Verifying authsvc at ${BASE_URL}"
echo

# Health (liveness)
if curl -sf "${BASE_URL}/health" | jq -e '.status == "ok"' >/dev/null 2>&1; then
  ok "/health"
else
  fail "/health"
fi

# Readiness (DB + Redis)
if curl -sf "${BASE_URL}/ready" | jq -e '.status == "ready"' >/dev/null 2>&1; then
  ok "/ready"
else
  fail "/ready (database or redis unreachable)"
fi

# OIDC discovery
discovery_json="$(curl -sf "${BASE_URL}/.well-known/openid-configuration" 2>/dev/null || true)"
if [[ -z "$discovery_json" ]]; then
  fail "/.well-known/openid-configuration"
else
  issuer="$(jq -r '.issuer // empty' <<<"$discovery_json")"
  if [[ -z "$issuer" ]]; then
    fail "openid-configuration missing issuer"
  else
    if [[ -n "$EXPECTED_ISSUER" && "$issuer" != "$EXPECTED_ISSUER" ]]; then
      fail "issuer mismatch (got ${issuer}, want ${EXPECTED_ISSUER})"
    else
      ok "issuer=${issuer}"
    fi
  fi
  if jq -e '.grant_types_supported | index("password")' <<<"$discovery_json" >/dev/null 2>&1; then
    fail "password grant advertised in openid-configuration"
  else
    ok "password grant not in discovery"
  fi
fi

# JWKS
jwks_keys="$(curl -sf "${BASE_URL}/.well-known/jwks.json" | jq -r '.keys | length' 2>/dev/null || echo 0)"
if [[ "${jwks_keys:-0}" -ge 1 ]]; then
  ok "/.well-known/jwks.json keys=${jwks_keys}"
else
  fail "/.well-known/jwks.json (no keys)"
fi

# Security headers (production)
hsts="$(header_value strict-transport-security "${BASE_URL}/health")"
if [[ -n "$hsts" ]]; then
  ok "HSTS present"
else
  fail "missing Strict-Transport-Security"
fi
csp="$(header_value content-security-policy "${BASE_URL}/health")"
if [[ -n "$csp" ]]; then
  ok "CSP present"
else
  fail "missing Content-Security-Policy"
fi

# Metrics must not be public in production
metrics_unauth="$(http_code "${BASE_URL}/metrics")"
if [[ "$metrics_unauth" == "401" ]]; then
  ok "/metrics rejects unauthenticated requests"
elif [[ "$metrics_unauth" == "200" ]]; then
  fail "/metrics is public (set METRICS_BEARER_TOKEN in production)"
else
  fail "/metrics unexpected status ${metrics_unauth} without token"
fi

if [[ -n "$METRICS_TOKEN" ]]; then
  metrics_auth="$(http_code -H "Authorization: Bearer ${METRICS_TOKEN}" "${BASE_URL}/metrics")"
  if [[ "$metrics_auth" == "200" ]]; then
    ok "/metrics accepts bearer token"
    if curl -sf -H "Authorization: Bearer ${METRICS_TOKEN}" "${BASE_URL}/metrics" | grep -q 'authsvc_http_request_duration_seconds'; then
      ok "/metrics exposes request histogram"
    else
      fail "/metrics missing authsvc_http_request_duration_seconds"
    fi
  else
    fail "/metrics with bearer returned ${metrics_auth}"
  fi
fi

# Admin console session API (httpOnly cookie flow; no localStorage)
session_status="$(http_code "${BASE_URL}/admin/session")"
if [[ "$session_status" == "200" ]]; then
  ok "/admin/session status endpoint"
else
  fail "/admin/session returned ${session_status}"
fi

# Compliance posture (requires admin JWT or bootstrap token with admin permission)
if [[ -n "$ADMIN_TOKEN" ]]; then
  compliance_json="$(curl -sf -H "Authorization: Bearer ${ADMIN_TOKEN}" \
    "${BASE_URL}/v1/compliance/status" 2>/dev/null || true)"
  if [[ -z "$compliance_json" ]]; then
    fail "/v1/compliance/status (unauthorized or error)"
  else
    pg_disabled="$(jq -r '.password_grant_disabled // false' <<<"$compliance_json")"
    cookie_secure="$(jq -r '.cookie_secure // false' <<<"$compliance_json")"
    key_rotation_due="$(jq -r '.jwt_key_rotation_due // false' <<<"$compliance_json")"
    if [[ "$pg_disabled" == "true" ]]; then
      ok "password_grant_disabled=true"
    else
      fail "password_grant_disabled is not true"
    fi
    if [[ "$cookie_secure" == "true" ]]; then
      ok "cookie_secure=true"
    else
      fail "cookie_secure is not true"
    fi
    if [[ "$key_rotation_due" == "true" ]]; then
      fail "jwt_key_rotation_due=true (rotate signing keys)"
    else
      ok "jwt_key_rotation_due=false"
    fi
  fi
else
  echo "SKIP /v1/compliance/status (set ADMIN_ACCESS_TOKEN to verify)"
fi

# Password grant must be disabled at token endpoint
password_grant_code="$(curl -s -o /dev/null -w '%{http_code}' \
  -X POST "${BASE_URL}/oauth/token" \
  -H 'Content-Type: application/json' \
  -d '{"grant_type":"password","client_id":"verify","username":"x","password":"y"}')"
if [[ "$password_grant_code" == "400" || "$password_grant_code" == "401" ]]; then
  ok "password grant not accepted (${password_grant_code})"
else
  fail "password grant returned ${password_grant_code} (expected 400/401 in production)"
fi

# Rate limit returns 429 (not 403) when exceeded — optional smoke via repeated health checks
rate_limit_hit=0
for _ in $(seq 1 5); do
  code="$(http_code "${BASE_URL}/health")"
  if [[ "$code" == "429" ]]; then
    rate_limit_hit=1
    break
  fi
done
if [[ "$rate_limit_hit" == "1" ]]; then
  retry_after="$(header_value retry-after "${BASE_URL}/health")"
  if [[ -n "$retry_after" ]]; then
    ok "rate limit returns 429 with Retry-After"
  else
    fail "rate limit 429 missing Retry-After header"
  fi
else
  echo "SKIP rate limit 429 semantics (threshold not hit in smoke test)"
fi

echo
if [[ "$failures" -gt 0 ]]; then
  echo "${failures} check(s) failed"
  exit 1
fi
echo "All checks passed."
