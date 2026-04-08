#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
RULE_SOURCE="$REPO_ROOT/infra/kali/auditd/agentic-soc.rules"
RULE_DEST="/etc/audit/rules.d/agentic-soc.rules"
SERVICE_PATH="/etc/systemd/system/agentic-soc-audit-bridge.service"
RUN_USER="${SUDO_USER:-$USER}"
RUN_HOME="$(getent passwd "$RUN_USER" | cut -d: -f6)"
STATE_DIR="$RUN_HOME/.local/state/agentic-soc-core"

if [[ ! -f "$REPO_ROOT/.env.production" ]]; then
  echo "Missing $REPO_ROOT/.env.production" >&2
  exit 1
fi

sudo apt update
sudo apt install -y auditd audispd-plugins python3
sudo install -D -m 0644 "$RULE_SOURCE" "$RULE_DEST"
sudo mkdir -p /var/log/audit
sudo augenrules --load || sudo service auditd restart

mkdir -p "$STATE_DIR"

cat <<EOF | sudo tee "$SERVICE_PATH" >/dev/null
[Unit]
Description=Agentic SOC Kali auditd bridge
After=network-online.target auditd.service docker.service
Wants=network-online.target

[Service]
Type=simple
User=$RUN_USER
WorkingDirectory=$REPO_ROOT
ExecStart=/usr/bin/python3 $REPO_ROOT/tools/kali-audit-bridge/auditd_to_normalizer.py --env-file $REPO_ROOT/.env.production --normalizer-url http://127.0.0.1:8001 --state-file $STATE_DIR/auditd-bridge-state.json
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now agentic-soc-audit-bridge.service
sudo systemctl status --no-pager agentic-soc-audit-bridge.service
