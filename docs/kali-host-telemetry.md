# Kali Host Telemetry

This guide connects real process execution on a Kali VM to Agentic SOC Core without requiring a full Wazuh agent deployment.

## What It Uses

- `auditd` for process execution telemetry
- a small Python collector under `tools/kali-audit-bridge/`
- the existing normalizer `POST /ingest/wazuh` path

## Install

From the repo root on Kali:

```bash
chmod +x tools/kali-audit-bridge/install-kali-audit-bridge.sh
./tools/kali-audit-bridge/install-kali-audit-bridge.sh
```

## Verify

```bash
systemctl status --no-pager agentic-soc-audit-bridge.service
journalctl -u agentic-soc-audit-bridge.service -f
```

## Replay Recent Audit Events

```bash
python3 tools/kali-audit-bridge/auditd_to_normalizer.py \
  --env-file .env.production \
  --normalizer-url http://127.0.0.1:8001 \
  --state-file /tmp/agentic-audit-bridge-state.json \
  --from-start \
  --once
```

## Detection Coverage

- encoded or inline shell commands
- download-and-execute patterns
- reverse-shell-like command chains
- persistence-like commands such as `crontab` or `systemctl enable`

## Tradeoff

This bridge is intentionally lightweight and demo-focused. It gives you a practical live-telemetry path for Kali without replacing a full Wazuh, Sysmon for Linux, Falco, or EDR deployment.
