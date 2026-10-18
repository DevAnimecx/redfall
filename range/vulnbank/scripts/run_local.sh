#!/usr/bin/env bash
# Boot vulnbank against a local Postgres (used when Docker is unavailable).
# Usage: scripts/run_local.sh [start|stop|status]
#
# The port is the source of truth: any process listening on it is killed before a
# new one starts, and startup fails if the recorded pid is not the real listener.
# Without this an orphaned server silently serves stale code and every gate that
# depends on "the app I just built" reports the wrong answer.
set -euo pipefail

cd "$(dirname "$0")/.."
PORT="${PORT:-4000}"
LOG=/tmp/vulnbank.log
PIDFILE=/tmp/vulnbank.pid

export PORT
export DB_HOST="${DB_HOST:-127.0.0.1}"
export DB_PORT="${DB_PORT:-5432}"
export DB_NAME="${DB_NAME:-vulnbank}"
export DB_USER="${DB_USER:-vulnbank}"
export DATABASE_URL="${DATABASE_URL:-postgresql://vulnbank:Sup3rS3cretBankPwd!@${DB_HOST}:${DB_PORT}/${DB_NAME}}"
export UPLOAD_DIR="${UPLOAD_DIR:-$PWD/uploads}"

port_pids() {
  ss -lntpH "sport = :${PORT}" 2>/dev/null | grep -oE 'pid=[0-9]+' | cut -d= -f2 | sort -u
}

stop_port() {
  local pids
  pids="$(port_pids || true)"
  if [[ -f "$PIDFILE" ]]; then
    pids="$pids $(cat "$PIDFILE" 2>/dev/null || true)"
  fi
  for pid in $pids; do
    [[ -n "$pid" ]] && kill "$pid" 2>/dev/null || true
  done
  for _ in $(seq 1 20); do
    [[ -z "$(port_pids || true)" ]] && break
    sleep 0.5
  done
  local left
  left="$(port_pids || true)"
  if [[ -n "$left" ]]; then
    for pid in $left; do kill -9 "$pid" 2>/dev/null || true; done
    sleep 1
  fi
  rm -f "$PIDFILE"
}

case "${1:-start}" in
  start)
    stop_port
    npm run build >/tmp/vulnbank_build.log 2>&1 || { echo "build failed:"; tail -30 /tmp/vulnbank_build.log; exit 1; }
    nohup node dist/server.js > "$LOG" 2>&1 &
    echo $! > "$PIDFILE"
    started="$(cat "$PIDFILE")"
    for _ in $(seq 1 60); do
      if curl -fsS "http://127.0.0.1:${PORT}/health" >/dev/null 2>&1; then
        listener="$(port_pids || true)"
        if [[ "$listener" != "$started" ]]; then
          echo "ERROR: :${PORT} is served by pid ${listener:-none}, not the process we started (${started})"
          tail -20 "$LOG"
          exit 1
        fi
        echo "vulnbank up on :${PORT} (pid ${started})"
        exit 0
      fi
      if ! kill -0 "$started" 2>/dev/null; then
        echo "vulnbank exited during startup; log:"; tail -30 "$LOG"; exit 1
      fi
      sleep 1
    done
    echo "vulnbank failed to become healthy; log:"; tail -40 "$LOG"; exit 1
    ;;
  stop)
    stop_port
    echo "stopped"
    ;;
  status)
    curl -fsS "http://127.0.0.1:${PORT}/health" || echo "not healthy"
    ;;
  *)
    echo "usage: $0 [start|stop|status]"; exit 2
    ;;
esac
