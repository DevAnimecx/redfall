#!/bin/sh
# Redfall installer for Linux and macOS.
#
#   ./scripts/install.sh          install from this checkout
#   sh scripts/install.sh         same, from any POSIX shell
#
# To install without a checkout, download this file first, read it, then run
# it - Redfall's own doctrine applies to installers too:
#
#   curl -fsSLO https://raw.githubusercontent.com/DevAnimecx/redfall/main/scripts/install.sh
#   sh install.sh
#
# What it does:
#   * finds a Python >= 3.12
#   * installs Redfall with pipx when pipx is available (isolated, recommended),
#     otherwise into a private virtualenv under ~/.redfall - never system-wide,
#     never privileged
#   * runs `redfall doctor` so the host's real capability report is the last
#     thing you see
#
# Environment:
#   REDFALL_SOURCE     package source to install (default: this checkout when
#                      run from one, else git+https://github.com/DevAnimecx/redfall)
#   REDFALL_HOME       virtualenv location when pipx is not used (default ~/.redfall)
#   REDFALL_PYTHON     interpreter to use (default: the best python3 found)
#   REDFALL_NO_DOCTOR  set to 1 to skip the final doctor report
#   REDFALL_NO_PIPX    set to 1 to always use the private virtualenv
set -eu

REPO_URL="https://github.com/DevAnimecx/redfall"

SOURCE="${REDFALL_SOURCE:-}"
if [ -z "$SOURCE" ]; then
    script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" 2>/dev/null && pwd || pwd)
    if [ -f "$script_dir/../pyproject.toml" ] && grep -q '^name = "redfall"' "$script_dir/../pyproject.toml"; then
        SOURCE="$script_dir/.."
    else
        SOURCE="git+$REPO_URL"
    fi
fi

PY="${REDFALL_PYTHON:-}"
if [ -z "$PY" ]; then
    for candidate in python3.13 python3.12 python3 python; do
        if command -v "$candidate" >/dev/null 2>&1; then
            PY="$candidate"
            break
        fi
    done
fi
if [ -z "$PY" ]; then
    echo "error: no Python interpreter found; install Python 3.12+ first" >&2
    exit 1
fi
if ! "$PY" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 12) else 1)'; then
    echo "error: Redfall needs Python 3.12+, but $PY is $("$PY" --version 2>&1)" >&2
    exit 1
fi

DOCTOR=""
if [ "${REDFALL_NO_PIPX:-0}" != "1" ] && command -v pipx >/dev/null 2>&1; then
    echo "installing Redfall with pipx (isolated) from: $SOURCE"
    pipx install --force "$SOURCE"
    if command -v redfall >/dev/null 2>&1; then
        DOCTOR="redfall"
    else
        echo "note: the pipx bin directory is not on PATH; run 'pipx ensurepath', restart the shell, then: redfall doctor"
    fi
else
    ROOT="${REDFALL_HOME:-$HOME/.redfall}"
    VENV="$ROOT/venv"
    echo "installing Redfall into a private virtualenv at: $VENV"
    "$PY" -m venv "$VENV"
    "$VENV/bin/python" -m pip install --quiet --upgrade pip
    "$VENV/bin/python" -m pip install --quiet "$SOURCE"
    DOCTOR="$VENV/bin/redfall"
    case ":$PATH:" in
        *":$VENV/bin:"*) ;;
        *) echo "note: add $VENV/bin to PATH to call 'redfall' directly:"
           echo "  export PATH=\"$VENV/bin:\$PATH\"" ;;
    esac
fi

echo
echo "Redfall 0.1.0 installed."
if [ "${REDFALL_NO_DOCTOR:-0}" != "1" ]; then
    if [ -n "$DOCTOR" ]; then
        echo "running: $DOCTOR doctor"
        # A missing prerequisite is the host's answer, not an installer failure.
        "$DOCTOR" doctor || echo "note: doctor reported missing prerequisites - that report is the point; see BLOCKED.md."
    fi
fi
