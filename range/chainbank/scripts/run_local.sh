#!/usr/bin/env bash
# Boot chainbank against a local Postgres (used when Docker is unavailable).
#
# The port owner is the source of truth for "is it running": a stale pidfile is
# not evidence, because an orphaned listener silently serves the old build.
set -euo pipefail

cd "$(dirname "$0")/.."

PORT="${PORT:-4002}"
LOG=/tmp/chainbank.log
PIDFILE=/tmp/chainbank.pid

export PORT
export DB_HOST="${DB_HOST:-127.0.0.1}"
export DB_PORT="${DB_PORT:-5432}"
export DB_NAME="${DB_NAME:-chainbank}"
export DB_USER="${DB_USER:-chainbank}"
export DB_PASSWORD="${DB_PASSWORD:-Chainbank!Pwd}"
export DATABASE_URL="postgresql://${DB_USER}:${DB_PASSWORD}@${DB_HOST}:${DB_PORT}/${DB_NAME}"
export CHAINBANK_PLUGIN_DIR="${CHAINBANK_PLUGIN_DIR:-/tmp/chainbank-plugins}"
export CHAINBANK_UPLOAD_DIR="${CHAINBANK_UPLOAD_DIR:-/tmp/chainbank-uploads}"

port_pids() {
  ss -lntpH "sport = :${PORT}" 2>/dev/null | grep -oE 'pid=[0-9]+' | cut -d= -f2 | sort -u
}

stop_all() {
  local pids
  pids="$(port_pids || true)"
  pids="$pids $(cat "$PIDFILE" 2>/dev/null || true)"
  for pid in $pids; do
    [[ -n "$pid" ]] && kill "$pid" 2>/dev/null || true
  done
  for _ in $(seq 1 30); do
    [[ -z "$(port_pids || true)" ]] && break
    sleep 0.2
  done
  local left
  left="$(port_pids || true)"
  if [[ -n "$left" ]]; then
    for pid in $left; do kill -9 "$pid" 2>/dev/null || true; done
  fi
  rm -f "$PIDFILE"
}

case "${1:-start}" in
  start)
    stop_all
    rm -rf "$CHAINBANK_PLUGIN_DIR" "$CHAINBANK_UPLOAD_DIR"
    mkdir -p "$CHAINBANK_PLUGIN_DIR" "$CHAINBANK_UPLOAD_DIR"
    npm run build >/tmp/chainbank_build.log 2>&1 || { echo "build failed:"; tail -30 /tmp/chainbank_build.log; exit 1; }
    npx ts-node src/db/seed.ts >>"$LOG" 2>&1
    nohup node dist/server.js >>"$LOG" 2>&1 &
    started=$!
    echo "$started" >"$PIDFILE"
    for _ in $(seq 1 60); do
      if curl -fsS "http://127.0.0.1:${PORT}/health" >/dev/null 2>&1; then
        listener="$(port_pids || true)"
        if [[ "$listener" != *"$started"* ]]; then
          echo "ERROR: :${PORT} is served by pid ${listener:-none}, not the process we started (${started})"
          exit 1
        fi
        echo "chainbank up on :${PORT} (pid ${started})"
        exit 0
      fi
      sleep 0.5
    done
    echo "chainbank did not become healthy; log tail:"; tail -20 "$LOG"; exit 1
    ;;
  stop)
    stop_all
    echo "chainbank stopped"
    ;;
  status)
    curl -fsS "http://127.0.0.1:${PORT}/health" || echo "not healthy"
    ;;
  *)
    echo "usage: $0 {start|stop|status}" >&2
    exit 2
    ;;
esac
