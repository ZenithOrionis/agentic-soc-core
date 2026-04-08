# Threat Scenarios

All scenarios are benign simulations and are safe to run repeatedly.

You can run them from the separate demo attack tool:

```powershell
.\attack.cmd list
.\attack.cmd run outbound-beacon --mode direct
.\attack.cmd run suspicious-script --mode direct
.\attack.cmd run bruteforce-success --mode direct
```

| Scenario | Trigger | Detection Source | ATT&CK |
| --- | --- | --- | --- |
| Outbound beacon | `/scenarios/outbound-beacon` | Suricata-like EVE | T1071 |
| Suspicious script | `/scenarios/suspicious-script` | Wazuh-like alert | T1059 |
| Brute force + success | `/scenarios/bruteforce-success` | Wazuh-like alert | T1110, T1078 |
| Exfil burst | `/scenarios/exfil-burst` | Suricata-like EVE | T1567 |
| Persistence-like | `/scenarios/persistence-like` | Wazuh-like alert | T1037 |
| Suspicious download | `/scenarios/suspicious-download` | Wazuh-like alert | T1059 |
| Reverse-shell-like | `/scenarios/reverse-shell-like` | Suricata-like EVE | T1095 |

The simulator sends raw event shapes into the normalizer rather than executing malware or harmful shell behavior.

## Atomic Red Team

The project includes a guarded Atomic Red Team bridge under `tools/atomic-red-team`.

Preview matching atomics:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\atomic-red-team\Run-Atomic-SuspiciousScript.ps1
```

Emit safe SOC telemetry without running Atomic tests:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\atomic-red-team\Invoke-AgenticAtomic.ps1 -Scenario suspicious-script -Mode EmitTelemetry
```

Execute only after reviewing details and choosing explicit test numbers:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\atomic-red-team\Run-Atomic-SuspiciousScript.ps1 -Mode Execute -TestNumbers 1 -IUnderstandRisks
```
