# Kali Audit Bridge

This bridge makes real host process activity in Kali show up in Agentic SOC Core by:

1. Enabling `auditd` exec logging.
2. Tailing `/var/log/audit/audit.log`.
3. Detecting suspicious shell, download-execute, reverse-shell-like, and persistence-like command lines.
4. Posting Wazuh-like alerts into the normalizer.

## Install

From the repo root on Kali:

```bash
chmod +x tools/kali-audit-bridge/install-kali-audit-bridge.sh
./tools/kali-audit-bridge/install-kali-audit-bridge.sh
```

## Manual Run

```bash
python3 tools/kali-audit-bridge/auditd_to_normalizer.py \
  --env-file .env.production \
  --normalizer-url http://127.0.0.1:8001 \
  --from-start
```

## Replay Recent Events Once

```bash
python3 tools/kali-audit-bridge/auditd_to_normalizer.py \
  --env-file .env.production \
  --normalizer-url http://127.0.0.1:8001 \
  --state-file /tmp/agentic-audit-bridge-state.json \
  --from-start \
  --once
```

## What It Detects

- Encoded or inline shell commands
- Download-and-execute patterns
- Reverse-shell-like command chains
- Persistence-like commands such as `crontab` or `systemctl enable`
