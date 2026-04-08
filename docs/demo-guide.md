# Demo Guide

1. Start the stack:

```bash
make up
```

Windows PowerShell without GNU Make:

```powershell
.\soc.cmd up
```

2. Open <http://localhost:8080>.

3. Trigger each scenario from the UI or with:

```bash
make demo-scenario-1
make demo-scenario-2
make demo-scenario-3
```

Windows PowerShell:

```powershell
.\soc.cmd demo-scenario-1
.\soc.cmd demo-scenario-2
.\soc.cmd demo-scenario-3
```

4. Review incidents in the UI.

5. Download PDFs from the report links or regenerate all reports:

```bash
make generate-reports
```

Windows PowerShell:

```powershell
.\soc.cmd generate-reports
```

Expected outcome:

- At least three incidents are created.
- `block_ip`, `create_case`, and `generate_report` actions are recorded.
- Scenario 1 also records demo quarantine state.
- Scenario 2 records artifact collection and benign process-kill marker actions.
