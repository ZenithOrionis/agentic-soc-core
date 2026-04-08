# Atomic Red Team Bridge

This folder integrates Atomic Red Team into Agentic SOC Core safely.

The default attack backend now routes to this Atomic bridge. The default mode is controlled by `.env.atomic`. The generated local default is `Preview`, which lists matching atomics for a scenario. Nothing executes unless `.env.atomic` sets `ATOMIC_DEFAULT_MODE=Execute`, `ATOMIC_REAL_ATTACKS_ENABLED=true`, and explicit test numbers for the scenario.

## Modes

- `EmitTelemetry`: uses Agentic SOC's safe telemetry simulator, no Atomic execution.
- `Preview`: shows matching Atomic Red Team details.
- `CheckPrereqs`: checks prerequisites for matching Atomic tests.
- `Execute`: executes selected test numbers only and requires `-IUnderstandRisks`.
- `Cleanup`: runs Atomic cleanup for the selected technique/test numbers.

## Example

Safe telemetry:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\atomic-red-team\Invoke-AgenticAtomic.ps1 -Scenario outbound-beacon -Mode EmitTelemetry
```

Preview Atomic Red Team tests:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\atomic-red-team\Invoke-AgenticAtomic.ps1 -Scenario suspicious-script -Mode Preview
```

Check prerequisites for explicit test numbers:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\atomic-red-team\Invoke-AgenticAtomic.ps1 -Scenario suspicious-script -Mode CheckPrereqs -TestNumbers 1
```

Execute explicit selected atomics only:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\atomic-red-team\Invoke-AgenticAtomic.ps1 -Scenario suspicious-script -Mode Execute -TestNumbers 1 -IUnderstandRisks
```

## Make Atomic Execution The Default

Edit `.env.atomic`:

```env
ATOMIC_DEFAULT_MODE=Execute
ATOMIC_REAL_ATTACKS_ENABLED=true
ATOMIC_TESTS_SUSPICIOUS_SCRIPT=1
```

Then:

```powershell
.\soc.cmd attack-script
```

Do not set execute mode without previewing and selecting low-impact test numbers first.

## Phone Triggering

The mobile console can trigger Atomic through the same default bridge:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\demo-attack-runner\ps1\Start-MobileAttackConsole.ps1 -Backend atomic
```

This is still controlled by `.env.atomic`. A phone tap will not execute a real Atomic test unless:

- `ATOMIC_DEFAULT_MODE=Execute`
- `ATOMIC_REAL_ATTACKS_ENABLED=true`
- the scenario has explicit `ATOMIC_TESTS_*` numbers configured

This prevents accidental execution of an entire technique from a mobile browser.

Cleanup:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\atomic-red-team\Invoke-AgenticAtomic.ps1 -Scenario suspicious-script -Mode Cleanup -TestNumbers 1
```

## Expected Local Paths

By default the bridge expects:

- `C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1`
- `C:\AtomicRedTeam\atomics`

Override with:

```powershell
-AtomicRedTeamPath "D:\tools\AtomicRedTeam"
-ModulePath "D:\tools\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1"
-AtomicsPath "D:\tools\AtomicRedTeam\atomics"
```
