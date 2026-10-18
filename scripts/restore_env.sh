#!/usr/bin/env bash
# Restore the host services and dependencies Redfall's tests and scans need.
#
# The sandbox this repo is developed in is ephemeral: installed packages, the
# Postgres cluster, the Redis daemon and the Docker daemon do not survive a
# recycle, so every green result has to be re-established before it can be
# trusted. This script is idempotent — run it at the top of any session.
#
# It does NOT invent capability the host lacks. If Docker cannot start, this
# script says so and exits non-zero rather than pretending.
set -uo pipefail

fail=0
say() { printf '%-24s %s\n' "$1" "$2"; }

# ---------------------------------------------------------------- Postgres ---
if ! command -v pg_lsclusters >/dev/null 2>&1; then
  sudo -n apt-get install -y postgresql >/dev/null 2>&1
fi
if command -v pg_lsclusters >/dev/null 2>&1; then
  ver=$(pg_lsclusters -h 2>/dev/null | awk '{print $1; exit}')
  sudo -n pg_ctlcluster "$ver" main start >/dev/null 2>&1
  if sudo -n -u postgres psql -tAc 'select 1' >/dev/null 2>&1; then
    say postgres "up (cluster $ver main)"
    # Roles and databases the range targets expect.
    sudo -n -u postgres psql -tAc \
      "SELECT 1 FROM pg_roles WHERE rolname='vulnbank'" | grep -q 1 || \
      sudo -n -u postgres psql -c \
        "CREATE ROLE vulnbank LOGIN PASSWORD 'Sup3rS3cretBankPwd!'" >/dev/null 2>&1
    sudo -n -u postgres psql -tAc \
      "SELECT 1 FROM pg_roles WHERE rolname='chainbank'" | grep -q 1 || \
      sudo -n -u postgres psql -c \
        "CREATE ROLE chainbank LOGIN PASSWORD 'Chainbank!Pwd'" >/dev/null 2>&1
    # `redfall` authenticates over TCP with a password; tests/test_llm.py
    # connects as postgresql://redfall:redfall@localhost:5432/redfall.
    sudo -n -u postgres psql -tAc \
      "SELECT 1 FROM pg_roles WHERE rolname='redfall'" | grep -q 1 || \
      sudo -n -u postgres psql -c \
        "CREATE ROLE redfall LOGIN PASSWORD 'redfall'" >/dev/null 2>&1
    sudo -n -u postgres psql -c \
      "ALTER ROLE redfall WITH PASSWORD 'redfall'" >/dev/null 2>&1
    # `redfall` owns redfall_test and must be able to CREATE in its public
    # schema: test_adaptive_scan.py drops and recreates that schema every
    # session, and connects as vulnbank, which needs USAGE as well.
    for db in vulnbank vulnbank_v2 chainbank redfall redfall_test; do
      sudo -n -u postgres psql -tAc \
        "SELECT 1 FROM pg_database WHERE datname='$db'" | grep -q 1 || \
        sudo -n -u postgres createdb -O redfall "$db" >/dev/null 2>&1
    done
    sudo -n -u postgres psql -c \
      "ALTER DATABASE chainbank OWNER TO chainbank" >/dev/null 2>&1
    sudo -n -u postgres psql -c \
      "ALTER DATABASE vulnbank OWNER TO vulnbank" >/dev/null 2>&1
    sudo -n -u postgres psql -c \
      "ALTER DATABASE redfall_test OWNER TO redfall" >/dev/null 2>&1
    for db in redfall redfall_test; do
      sudo -n -u postgres psql -d "$db" -c \
        "ALTER SCHEMA public OWNER TO redfall" >/dev/null 2>&1
      sudo -n -u postgres psql -d "$db" -c \
        "GRANT ALL ON SCHEMA public TO redfall" >/dev/null 2>&1
      sudo -n -u postgres psql -d "$db" -c \
        "GRANT ALL ON SCHEMA public TO vulnbank" >/dev/null 2>&1
    done
  else
    say postgres "FAILED to start"; fail=1
  fi
else
  say postgres "ABSENT (no pg_lsclusters)"; fail=1
fi

# -------------------------------------------------------------------- Redis ---
if ! command -v redis-cli >/dev/null 2>&1; then
  sudo -n apt-get install -y redis-server >/dev/null 2>&1
fi
if command -v redis-server >/dev/null 2>&1; then
  redis-cli ping >/dev/null 2>&1 || \
    (redis-server --daemonize yes >/dev/null 2>&1; sleep 2)
  redis-cli ping >/dev/null 2>&1 && say redis "up" || { say redis "FAILED"; fail=1; }
fi

# -------------------------------------------------------------- Python deps ---
python3 -c 'import sqlalchemy, flask, requests, tree_sitter_python' >/dev/null 2>&1 || \
  pip3 install --quiet sqlalchemy "psycopg[binary]" pyyaml \
    tree-sitter tree-sitter-javascript tree-sitter-typescript tree-sitter-python litellm \
    redis rich gitpython flask requests >/dev/null 2>&1
python3 -c 'import sqlalchemy, flask, requests, tree_sitter_python' >/dev/null 2>&1 \
  && say python-deps "ok" || { say python-deps "FAILED"; fail=1; }

# --------------------------------------------------------- range node deps ---
if [ ! -d range/vulnbank/node_modules ]; then
  (cd range/vulnbank && npm install --no-audit --no-fund >/dev/null 2>&1)
fi
for sibling in vulnbank-adaptive chainbank; do
  [ -d "range/$sibling" ] || continue
  [ -e "range/$sibling/node_modules" ] || \
    ln -sfn ../vulnbank/node_modules "range/$sibling/node_modules"
done
[ -d range/vulnbank/node_modules ] \
  && say node_modules "ok ($(ls range/vulnbank/node_modules | wc -l) pkgs)" \
  || { say node_modules "MISSING"; fail=1; }

# ------------------------------------------------------------------- Docker ---
# Real gVisor, not runc: Redfall executes every candidate exploit inside the
# Sentry user-space kernel. If runsc is absent the scan path is unavailable and
# that must be reported, not papered over.
if ! command -v docker >/dev/null 2>&1; then
  sudo -n apt-get install -y docker.io >/dev/null 2>&1
fi
if ! command -v runsc >/dev/null 2>&1; then
  sudo -n apt-get install -y runsc >/dev/null 2>&1
fi
if command -v docker >/dev/null 2>&1; then
  docker info >/dev/null 2>&1 || {
    if [ ! -f /etc/docker/daemon.json ]; then
      sudo -n mkdir -p /etc/docker
      printf '{ "runtimes": { "runsc": { "path": "/usr/bin/runsc" } } }\n' \
        | sudo -n tee /etc/docker/daemon.json >/dev/null
    fi
    (sudo -n dockerd >/tmp/dockerd.log 2>&1 &)
    for _ in $(seq 20); do docker info >/dev/null 2>&1 && break; sleep 1; done
  }
  # The CLI runs unprivileged; the socket must be reachable without sudo.
  [ -S /var/run/docker.sock ] && sudo -n chmod 666 /var/run/docker.sock
  if docker info >/dev/null 2>&1; then
    rt=$(docker info --format '{{json .Runtimes}}' 2>/dev/null)
    case "$rt" in
      *runsc*) say docker "up, runsc registered" ;;
      *)       say docker "up, runsc NOT registered"; fail=1 ;;
    esac
  else
    say docker "FAILED to start"; fail=1
  fi
else
  say docker "ABSENT"; fail=1
fi

exit "$fail"
