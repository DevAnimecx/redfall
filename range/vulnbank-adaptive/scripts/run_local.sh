#!/usr/bin/env bash
# Boot vulnbank-adaptive against a local Postgres (used when Docker is unavailable).
#
# The port owner is the source of truth for "is it running": a stale pidfile is
# not evidence, because an orphaned listener silently serves the old build.
set -euo pipefail

cd "$(dirname "$0")/.."

PORT="${PORT:-4001}"
LOG=/tmp/vulnbank-v2.log
PIDFILE=/tmp/vulnbank-v2.pid

export PORT
export DB_HOST="${DB_HOST:-127.0.0.1}"
export DB_PORT="${DB_PORT:-5432}"
export DB_NAME="${DB_NAME:-vulnbank_v2}"
export DB_USER="${DB_USER:-vulnbank}"
export DB_PASSWORD="${DB_PASSWORD:-Sup3rS3cretBankPwd!}"
export DATABASE_URL="${DATABASE_URL:-postgresql://vulnbank:Sup3rS3cretBankPwd!@${DB_HOST}:${DB_PORT}/${DB_NAME}}"
export JWT_SECRET="${JWT_SECRET:-test-only-jwt-secret-value}"
export STRIPE_WEBHOOK_SECRET="${STRIPE_WEBHOOK_SECRET:-whsec_test_only_value}"
export UPLOAD_DIR="${UPLOAD_DIR:-/tmp/vulnbank-v2-uploads}"

# The Redfall 0.1.0 surfaces are conditional. This script turns them on so the running
# application actually exposes what the manifest claims; the test suite exercises
# the other combinations separately.
export NODE_ENV="${NODE_ENV:-production}"
export FEATURE_BETA_EXPORT="${FEATURE_BETA_EXPORT:-on}"
export WEBHOOK_ENABLED="${WEBHOOK_ENABLED:-true}"
export PLUGIN_DIR="${PLUGIN_DIR:-$(pwd)/dist/plugins}"
# VULN-034: which module the dynamic import loads is an environment decision.
export PLUGIN_PATH="${PLUGIN_PATH:-$(pwd)/dist/plugins/envplugin.js}"

mkdir -p "$UPLOAD_DIR"

listener_pids() {
  ss -lntpH "sport = :${PORT}" 2>/dev/null | grep -oE 'pid=[0-9]+' | cut -d= -f2 | sort -u
}

case "${1:-start}" in
  start)
    for pid in $(listener_pids); do
      echo "killing existing listener on :${PORT} (pid ${pid})"
      kill "$pid" 2>/dev/null || true
    done
    sleep 1
    for pid in $(listener_pids); do
      kill -9 "$pid" 2>/dev/null || true
    done

    echo "building"
    npm run build >/tmp/vulnbank-v2_build.log 2>&1 || { echo "build failed:"; tail -30 /tmp/vulnbank-v2_build.log; exit 1; }

    echo "starting on :${PORT}"
    nohup node dist/server.js >"$LOG" 2>&1 &
    started=$!
    echo "$started" >"$PIDFILE"

    for _ in $(seq 1 60); do
      if curl -fsS "http://127.0.0.1:${PORT}/health" >/dev/null 2>&1; then
        listener=$(listener_pids | head -1)
        if [ -n "$listener" ] && [ "$listener" != "$started" ]; then
          echo "ERROR: :${PORT} is served by pid ${listener:-none}, not the process we started (${started})"
          exit 1
        fi
        echo "vulnbank-adaptive up on :${PORT} (pid ${started})"
        exit 0
      fi
      if ! kill -0 "$started" 2>/dev/null; then
        echo "vulnbank-adaptive exited during startup; log:"; tail -30 "$LOG"; exit 1
      fi
      sleep 0.5
    done
    echo "vulnbank-adaptive failed to become healthy; log:"; tail -40 "$LOG"; exit 1
    ;;

  stop)
    for pid in $(listener_pids); do
      echo "stopping listener on :${PORT} (pid ${pid})"
      kill "$pid" 2>/dev/null || true
    done
    rm -f "$PIDFILE"
    ;;

  status)
    echo "port ${PORT} listener: $(listener_pids | tr '\n' ' ')"
    curl -fsS "http://127.0.0.1:${PORT}/health" || echo "not healthy"
    ;;

  *)
    echo "usage: $0 {start|stop|status}" >&2
    exit 2
    ;;
esac
