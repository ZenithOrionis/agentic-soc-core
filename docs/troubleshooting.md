# Troubleshooting

| Symptom | Fix |
| --- | --- |
| UI shows no incidents | Trigger a scenario with `make demo-scenario-1` or use UI buttons. |
| `make` is not recognized in PowerShell | Use `.\soc.cmd up`, `.\soc.cmd demo-scenario-1`, `.\soc.cmd demo-scenario-2`, and `.\soc.cmd demo-scenario-3`. |
| Reports are missing | Run `make generate-reports` after incidents exist. |
| Compose services fail health checks | Run `make logs` and then `make reset` if state is stale. |
| Python unit tests cannot import dependencies | Create a virtual environment and install `requirements-dev.txt`. |
| PDF is a fallback | Check WeasyPrint native libraries if running outside Docker. |

The default demo does not alter host firewall rules. It records firewall/quarantine actions in the SOC state store.
