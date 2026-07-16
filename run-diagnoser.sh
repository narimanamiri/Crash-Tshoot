#!/usr/bin/env bash
# Crash-Tshoot Linux/macOS launcher
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"

if command -v python3 >/dev/null 2>&1; then
  PY=python3
elif command -v python >/dev/null 2>&1; then
  PY=python
else
  echo "Python 3 not found." >&2
  exit 1
fi

# Optional: request elevated for full journal/dmesg/SMART
exec "$PY" "$ROOT/run_diagnoser.py" "$@"
