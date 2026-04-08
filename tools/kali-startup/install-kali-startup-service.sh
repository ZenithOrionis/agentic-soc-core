#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SERVICE_PATH="/etc/systemd/system/agentic-soc-startup.service"

cat <<EOF | sudo tee "$SERVICE_PATH" >/dev/null
[Unit]
Description=AegisCore Kali startup automation
After=network-online.target docker.service auditd.service
Wants=network-online.target docker.service auditd.service

[Service]
Type=oneshot
WorkingDirectory=$REPO_ROOT
ExecStart=/bin/bash $REPO_ROOT/tools/kali-startup/start-agentic-soc-lab.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now agentic-soc-startup.service
sudo systemctl status --no-pager agentic-soc-startup.service
