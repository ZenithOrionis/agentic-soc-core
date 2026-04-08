#!/usr/bin/env bash
set -euo pipefail

HOST="${1:-127.0.0.1}"
PORT="${2:-8105}"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

echo
echo "AegisCore Adversary Lab"
echo "Open http://${HOST}:${PORT} in your browser."
echo

python3 "${REPO_ROOT}/tools/adversary-lab/adversary_lab_console.py" --host "${HOST}" --port "${PORT}"
