#!/usr/bin/env bash
# Start/stop local Postgres + Redis via Homebrew (default for authsvc dev).
set -euo pipefail

PG_SERVICE="${PG_SERVICE:-postgresql@18}"
REDIS_SERVICE="${REDIS_SERVICE:-redis}"
PG_BIN="${PG_BIN:-/opt/homebrew/opt/${PG_SERVICE}/bin}"
DATABASE_URL="${DATABASE_URL:-postgres://authsvc:authsvc@127.0.0.1:5432/authsvc}"
REDIS_URL="${REDIS_URL:-redis://127.0.0.1:6379}"

usage() {
  cat <<'EOF'
Usage: brew_services.sh <command>

Commands:
  up       Start Postgres + Redis (brew services) and ensure authsvc DB exists
  down     Stop Postgres + Redis brew services
  status   Show brew service status and connectivity
  wait     Block until Postgres and Redis accept connections

Environment:
  PG_SERVICE   Homebrew formula (default: postgresql@18)
  REDIS_SERVICE Homebrew formula (default: redis)
EOF
}

ensure_pg_path() {
  if [[ -d "$PG_BIN" ]]; then
    export PATH="$PG_BIN:$PATH"
  fi
}

start_services() {
  if ! command -v brew >/dev/null; then
    echo "Homebrew is required. Install from https://brew.sh"
    exit 1
  fi
  if ! brew list "$PG_SERVICE" >/dev/null 2>&1; then
    echo "Install Postgres: brew install $PG_SERVICE"
    exit 1
  fi
  if ! brew list "$REDIS_SERVICE" >/dev/null 2>&1; then
    echo "Install Redis: brew install $REDIS_SERVICE"
    exit 1
  fi

  brew services start "$PG_SERVICE"
  brew services start "$REDIS_SERVICE"
}

stop_services() {
  brew services stop "$REDIS_SERVICE" 2>/dev/null || true
  brew services stop "$PG_SERVICE" 2>/dev/null || true
}

ensure_authsvc_db() {
  ensure_pg_path
  psql -d postgres -v ON_ERROR_STOP=1 <<'SQL'
DO $$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'authsvc') THEN
    CREATE ROLE authsvc WITH LOGIN PASSWORD 'authsvc';
  END IF;
END
$$;
SELECT 'CREATE DATABASE authsvc OWNER authsvc'
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'authsvc')\gexec
GRANT ALL PRIVILEGES ON DATABASE authsvc TO authsvc;
SQL
}

wait_for_services() {
  ensure_pg_path
  for _ in $(seq 1 30); do
    if psql -d postgres -c "SELECT 1" >/dev/null 2>&1; then
      break
    fi
    sleep 1
  done
  psql -d postgres -c "SELECT 1" >/dev/null 2>&1 || {
    echo "Postgres did not become ready"
    exit 1
  }

  for _ in $(seq 1 30); do
    if redis-cli ping 2>/dev/null | grep -q PONG; then
      return 0
    fi
    sleep 1
  done
  echo "Redis did not become ready"
  exit 1
}

print_status() {
  brew services list | grep -E "${PG_SERVICE}|${REDIS_SERVICE}" || true
  echo ""
  echo "DATABASE_URL=$DATABASE_URL"
  echo "REDIS_URL=$REDIS_URL"
  if wait_for_services 2>/dev/null; then
    psql "$DATABASE_URL" -c "SELECT current_database(), current_user;" 2>/dev/null || true
    redis-cli ping 2>/dev/null || true
  else
    echo "Services not ready"
    exit 1
  fi
}

cmd="${1:-up}"
case "$cmd" in
  up)
    start_services
    wait_for_services
    ensure_authsvc_db
    echo "Homebrew Postgres + Redis are up."
    echo "DATABASE_URL=$DATABASE_URL"
    echo "REDIS_URL=$REDIS_URL"
    ;;
  down)
    stop_services
    echo "Stopped $PG_SERVICE and $REDIS_SERVICE."
    ;;
  status)
    print_status
    ;;
  wait)
    wait_for_services
    ;;
  -h|--help|help)
    usage
    ;;
  *)
    usage
    exit 1
    ;;
esac
