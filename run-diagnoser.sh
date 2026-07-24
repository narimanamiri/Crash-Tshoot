#!/usr/bin/env bash
# Crash-Tshoot — Linux / macOS / BSD launcher
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"

if command -v python3 >/dev/null 2>&1; then
  PY=python3
elif command -v python >/dev/null 2>&1; then
  PY=python
else
  echo "Python 3.10+ is required." >&2
  exit 1
fi

# On Linux/macOS, elevated rights improve journal/dmesg/SMART/log show coverage
if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
  exec "$PY" "$ROOT/run_diagnoser.py" --help
fi

exec "$PY" "$ROOT/run_diagnoser.py" "$@"
