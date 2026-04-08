# AegisCore Adversary Lab

This is a dedicated lab console for running Atomic Red Team-backed adversary emulation from one place during demonstrations.

It is designed for:

- previewing Atomic tests by scenario
- checking prerequisites
- executing explicitly configured lab tests
- cleaning up after runs
- emitting matching SOC telemetry for demo validation
- keeping a local run history

It is not an unconstrained attack launcher. Execution remains bounded to the lab scenarios and explicit test numbers configured in `.env.atomic`.

## Start The Console

Windows PowerShell:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\adversary-lab\ps1\Start-AegisCoreAdversaryLab.ps1
```

Kali / Linux:

```bash
./tools/adversary-lab/start-aegiscore-adversary-lab.sh
```

Python directly:

```bash
python tools/adversary-lab/adversary_lab_console.py --host 127.0.0.1 --port 8105
```

Open:

```text
http://127.0.0.1:8105
```

## Remote Demo Mode

If you need to expose it to another device on the same lab network, start with remote mode enabled:

```bash
python tools/adversary-lab/adversary_lab_console.py --host 0.0.0.0 --port 8105 --allow-remote
```

The console prints a tokenized URL. Share that only inside your disposable lab.

## Execution Rules

The console reads `.env.atomic` on every run. Execution will succeed only when:

- `ATOMIC_REAL_ATTACKS_ENABLED=true`
- the target scenario has explicit `ATOMIC_TESTS_*` values

Example:

```env
ATOMIC_RED_TEAM_PATH=/opt/AtomicRedTeam
ATOMIC_DEFAULT_MODE=Execute
ATOMIC_REAL_ATTACKS_ENABLED=true
ATOMIC_TESTS_SUSPICIOUS_SCRIPT=1
ATOMIC_TESTS_SUSPICIOUS_DOWNLOAD=1
```

The console does not execute every Atomic for a technique. It uses your selected test numbers only.

## Local Run History

Runs are stored outside the repo:

- Windows: `%LOCALAPPDATA%\\AegisCore\\adversary-lab\\run-history.jsonl`
- Linux: `~/.local/state/aegiscore/adversary-lab/run-history.jsonl`

## Recommended Demo Flow

1. Preview the scenario.
2. Check prerequisites.
3. Execute a low-impact selected test number in your disposable VM.
4. Watch the SOC ingest and incident flow.
5. Run cleanup.
