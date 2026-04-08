# Kali Startup Automation

This automation brings up the full Kali lab at boot or on demand:

- starts Docker
- starts `auditd`
- starts the production SOC stack with the `ai` profile
- ensures the configured Ollama model exists
- installs or restarts the Kali audit bridge
- waits for the core APIs to become healthy

## Run Manually

```bash
chmod +x tools/kali-startup/start-agentic-soc-lab.sh
./tools/kali-startup/start-agentic-soc-lab.sh
```

## Install At Boot

```bash
chmod +x tools/kali-startup/install-kali-startup-service.sh
./tools/kali-startup/install-kali-startup-service.sh
```

## Check Status

```bash
systemctl status --no-pager agentic-soc-startup.service
journalctl -u agentic-soc-startup.service -n 100 --no-pager
```
