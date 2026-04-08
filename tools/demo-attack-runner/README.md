# Demo Attack Runner

This is a separate benign demo attack tool for AegisCore. It does not run malware, exploit code, or destructive commands. It only sends safe adversary-emulation events to the SOC demo.

For polished demonstrations where you want both the real Atomic execution and a guaranteed visible alert path, use the live-demo wrappers. They execute the real Atomic test first, then inject the matching SOC telemetry so the dashboard, case flow, and report update reliably.

Windows PowerShell:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\demo-attack-runner\ps1\Run-LiveDemo-SuspiciousScript.ps1
```

Kali / Linux:

```bash
chmod +x ./tools/demo-attack-runner/sh/*.sh
./tools/demo-attack-runner/sh/run-live-demo-suspicious-script.sh
```

## PowerShell Usage

List scenarios:

```powershell
.\attack.cmd list
```

Run through the simulator service in demo mode:

```powershell
.\attack.cmd run outbound-beacon
.\attack.cmd run suspicious-script
.\attack.cmd run bruteforce-success
```

## Direct PS1 Launchers

Each attack type also has a dedicated PowerShell script under `tools/demo-attack-runner/ps1`. The primary `Run-*` scripts now route through the Atomic Red Team default backend.

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\demo-attack-runner\ps1\Run-OutboundBeacon.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\demo-attack-runner\ps1\Run-SuspiciousScript.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\demo-attack-runner\ps1\Run-BruteforceSuccess.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\demo-attack-runner\ps1\Run-ExfilBurst.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\demo-attack-runner\ps1\Run-PersistenceLike.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\demo-attack-runner\ps1\Run-SuspiciousDownload.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\demo-attack-runner\ps1\Run-ReverseShellLike.ps1
```

Run the three required demo scenarios together:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\demo-attack-runner\ps1\Run-AllCoreScenarios.ps1
```

Safe telemetry-only fallbacks are still available:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\demo-attack-runner\ps1\Run-Telemetry-OutboundBeacon.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\demo-attack-runner\ps1\Run-Telemetry-SuspiciousScript.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\demo-attack-runner\ps1\Run-Telemetry-BruteforceSuccess.ps1
```

## Phone Mode

Start a phone-friendly button console on your laptop:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\demo-attack-runner\ps1\Start-MobileAttackConsole.ps1
```

Atomic backend from phone:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\demo-attack-runner\ps1\Start-MobileAttackConsole.ps1 -Backend atomic
```

Atomic phone mode still uses `.env.atomic`. To execute real selected Atomic tests from the phone, first preview and choose test numbers, then set:

```env
ATOMIC_DEFAULT_MODE=Execute
ATOMIC_REAL_ATTACKS_ENABLED=true
ATOMIC_TESTS_SUSPICIOUS_SCRIPT=1
```

Then start the phone console with `-Backend atomic`.

The script prints a tokenized LAN URL such as:

```text
http://192.168.1.50:8099/?token=<random-token>
```

Open that URL on your phone while connected to the same Wi-Fi. Telemetry backend sends benign demo telemetry. Atomic backend calls the local Atomic bridge and remains constrained by `.env.atomic`.

Run direct to the normalizer, useful when production mode disables simulator services:

```powershell
.\attack.cmd run outbound-beacon --mode direct
```

The tool automatically reads `SOC_API_KEY` from `.env` or `.env.production` if either file exists.

## Docker Usage

```powershell
docker compose --profile demo-attacks run --rm demo-attack-runner list
docker compose --profile demo-attacks run --rm demo-attack-runner run outbound-beacon --mode direct --normalizer-url http://normalizer:8000
```

## Scenarios

- `outbound-beacon`
- `suspicious-script`
- `bruteforce-success`
- `exfil-burst`
- `persistence-like`
- `suspicious-download`
- `reverse-shell-like`
