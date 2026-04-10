#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "Usage: $0 <scenario>" >&2
  exit 1
fi

SCENARIO="$1"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"

echo
echo "AegisCore live demo launcher"
echo "Scenario: ${SCENARIO}"
echo "Step 1/2: executing the real Atomic test configured in .env.atomic"
echo

pwsh -NoProfile -ExecutionPolicy Bypass -File "${REPO_ROOT}/tools/atomic-red-team/Invoke-AgenticAtomicDefault.ps1" -Scenario "${SCENARIO}"

echo
echo "Step 2/2: injecting matching SOC telemetry so the AegisCore dashboard reflects the attack path."
echo

python3 "${REPO_ROOT}/tools/demo-attack-runner/attack_runner.py" run "${SCENARIO}" --mode direct --normalizer-url http://127.0.0.1:8001 --simulator-url http://127.0.0.1:8005 --delay 0.1
