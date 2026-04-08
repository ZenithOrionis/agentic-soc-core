#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "Usage: $0 <scenario>" >&2
  exit 1
fi

SCENARIO="$1"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"

echo
echo "AegisCore one-click attack launcher"
echo "Scenario: ${SCENARIO}"
echo "Using .env.atomic for execution mode, Atomic path, and selected test numbers."
echo

pwsh -NoProfile -ExecutionPolicy Bypass -File "${REPO_ROOT}/tools/atomic-red-team/Invoke-AgenticAtomicDefault.ps1" -Scenario "${SCENARIO}"
