#!/bin/bash
# Double-clickable on macOS (Terminal). Same as run-diagnoser.sh
cd "$(dirname "$0")"
exec ./run-diagnoser.sh "$@"
