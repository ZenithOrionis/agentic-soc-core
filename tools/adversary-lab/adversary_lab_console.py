from __future__ import annotations

import argparse
import json
import os
import secrets
import shutil
import subprocess
import sys
from dataclasses import dataclass
from datetime import UTC, datetime
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse


SCENARIOS = {
    "outbound-beacon": {
        "title": "Aegis Beacon Trace",
        "technique": "T1071.001",
        "summary": "Controlled callback patterns that resemble command-and-control beaconing.",
    },
    "suspicious-script": {
        "title": "Aegis Script Hunt",
        "technique": "T1059.003",
        "summary": "Suspicious inline shell and encoded execution patterns on the target host.",
    },
    "bruteforce-success": {
        "title": "Aegis Credential Breach",
        "technique": "T1110",
        "summary": "Repeated failed logins followed by a suspicious success in a disposable lab target.",
    },
    "exfil-burst": {
        "title": "Aegis Exfil Sweep",
        "technique": "T1041",
        "summary": "Exfiltration-like burst traffic to validate response and reporting flows.",
    },
    "persistence-like": {
        "title": "Aegis Persistence Probe",
        "technique": "T1053.005",
        "summary": "Scheduled task and startup-style persistence emulation with cleanup support.",
    },
    "suspicious-download": {
        "title": "Aegis Download Watch",
        "technique": "T1105",
        "summary": "Ingress tool transfer style emulation for download-and-execute visibility.",
    },
    "reverse-shell-like": {
        "title": "Aegis Callback Relay",
        "technique": "T1105",
        "summary": "Reverse-shell-like callback patterns scoped to controlled lab conditions only.",
    },
}

ACTION_MAP = {
    "preview": "Preview",
    "check_prereqs": "CheckPrereqs",
    "execute": "Execute",
    "cleanup": "Cleanup",
    "emit_telemetry": "EmitTelemetry",
}

PAGE = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>AegisCore Adversary Lab</title>
  <style>
    :root {
      color-scheme: dark;
      font-family: Inter, "Segoe UI", Arial, sans-serif;
      background:
        radial-gradient(circle at top, rgba(56, 189, 248, 0.15), transparent 28%),
        radial-gradient(circle at 80% 12%, rgba(251, 191, 36, 0.14), transparent 22%),
        linear-gradient(180deg, #060d19 0%, #0a1222 55%, #07111f 100%);
      color: #e5edf8;
    }
    * { box-sizing: border-box; }
    body { margin: 0; min-height: 100vh; padding: 24px; }
    header, .panel, .scenario {
      background: rgba(10, 18, 34, 0.88);
      border: 1px solid rgba(124, 145, 182, 0.16);
      border-radius: 20px;
      box-shadow: 0 24px 80px rgba(2, 8, 23, 0.45);
      backdrop-filter: blur(14px);
    }
    header { padding: 28px 30px; margin-bottom: 22px; }
    .eyebrow {
      text-transform: uppercase;
      letter-spacing: 0.22em;
      color: #6ee7f9;
      font-size: 12px;
      font-weight: 800;
      margin-bottom: 10px;
    }
    h1 { margin: 0 0 10px; font-size: clamp(34px, 5vw, 54px); letter-spacing: -0.04em; }
    h2 { margin: 0 0 8px; font-size: 24px; }
    p { color: #9fb2cf; line-height: 1.6; }
    .grid { display: grid; gap: 18px; grid-template-columns: 1.15fr 2fr; }
    .panel { padding: 22px; }
    .status-list { display: grid; gap: 12px; }
    .status-item {
      background: rgba(5, 12, 24, 0.74);
      border: 1px solid rgba(110, 231, 249, 0.12);
      border-radius: 14px;
      padding: 12px 14px;
    }
    .status-item strong { display: block; color: #f8fbff; margin-bottom: 4px; }
    .scenario-list { display: grid; gap: 16px; }
    .scenario { padding: 20px; }
    .meta { display: flex; gap: 10px; flex-wrap: wrap; margin: 8px 0 12px; }
    .pill {
      display: inline-flex;
      align-items: center;
      border-radius: 999px;
      padding: 6px 10px;
      font-size: 12px;
      font-weight: 700;
      border: 1px solid rgba(110, 231, 249, 0.14);
      color: #d9f7ff;
      background: rgba(8, 47, 73, 0.42);
    }
    .actions { display: flex; flex-wrap: wrap; gap: 10px; margin-top: 14px; }
    button {
      border: 1px solid rgba(110, 231, 249, 0.18);
      border-radius: 14px;
      background: linear-gradient(135deg, rgba(8, 47, 73, 0.98), rgba(14, 116, 144, 0.88));
      color: #f8fbff;
      padding: 11px 14px;
      font-weight: 800;
      cursor: pointer;
    }
    button.warn { background: linear-gradient(135deg, rgba(120, 53, 15, 0.95), rgba(180, 83, 9, 0.86)); }
    button.ghost { background: rgba(11, 19, 36, 0.95); }
    button:hover { border-color: rgba(251, 191, 36, 0.34); }
    #output, #history {
      white-space: pre-wrap;
      background: rgba(2, 8, 23, 0.92);
      border: 1px solid rgba(110, 231, 249, 0.12);
      border-radius: 16px;
      min-height: 220px;
      max-height: 460px;
      overflow: auto;
      padding: 14px;
      color: #dce5f3;
      font-size: 12px;
    }
    .split { display: grid; gap: 18px; grid-template-columns: 1fr 1fr; margin-top: 22px; }
    .hint {
      background: rgba(120, 53, 15, 0.18);
      border: 1px solid rgba(251, 191, 36, 0.2);
      border-radius: 14px;
      color: #fde68a;
      padding: 12px 14px;
      margin-top: 14px;
    }
    code { color: #c7f9ff; }
    @media (max-width: 1040px) {
      .grid, .split { grid-template-columns: 1fr; }
    }
  </style>
</head>
<body>
  <header>
    <div class="eyebrow">AegisCore Lab Platform</div>
    <h1>AegisCore Adversary Lab</h1>
    <p>Operator console for Atomic Red Team-driven adversary emulation in a disposable, authorized lab. This platform is designed for preview, prereq checks, controlled execution, cleanup, and SOC telemetry validation against your own demo environment.</p>
    <div class="hint">Execution remains bounded to your configured <code>.env.atomic</code> test numbers and lab target. Use only inside infrastructure you control.</div>
  </header>

  <section class="grid">
    <article class="panel">
      <div class="eyebrow">Lab Status</div>
      <h2>Atomic Control State</h2>
      <div id="status" class="status-list">Loading...</div>
    </article>
    <article class="panel">
      <div class="eyebrow">Scenario Catalog</div>
      <h2>Authorized Emulation Paths</h2>
      <div id="scenarios" class="scenario-list"></div>
    </article>
  </section>

  <section class="split">
    <article class="panel">
      <div class="eyebrow">Last Result</div>
      <h2>Run Output</h2>
      <pre id="output">Ready. Choose a scenario action.</pre>
    </article>
    <article class="panel">
      <div class="eyebrow">Recent Activity</div>
      <h2>Local Run History</h2>
      <pre id="history">Loading history...</pre>
    </article>
  </section>

  <script>
    let state = null;

    async function getJson(url, options) {
      const response = await fetch(url, options || {});
      const text = await response.text();
      let data;
      try { data = JSON.parse(text); } catch { data = { raw: text }; }
      if (!response.ok) {
        throw new Error(JSON.stringify(data, null, 2));
      }
      return data;
    }

    function renderStatus(status) {
      const el = document.getElementById("status");
      const items = [
        ["Default mode", status.atomic_default_mode],
        ["Real execution enabled", String(status.atomic_real_attacks_enabled)],
        ["Atomic path", status.atomic_red_team_path || "not set"],
        ["PowerShell runtime", status.powershell || "not found"],
        ["State file", status.history_path],
      ];
      el.innerHTML = items.map(([label, value]) =>
        `<div class="status-item"><strong>${label}</strong><span>${value}</span></div>`
      ).join("");
    }

    function renderScenarios(data) {
      const el = document.getElementById("scenarios");
      el.innerHTML = data.scenarios.map((scenario) => `
        <section class="scenario">
          <div class="eyebrow">${scenario.key}</div>
          <h2>${scenario.title}</h2>
          <p>${scenario.summary}</p>
          <div class="meta">
            <span class="pill">${scenario.technique}</span>
            <span class="pill">Configured tests: ${scenario.configured_tests || "none"}</span>
          </div>
          <div class="actions">
            <button class="ghost" onclick="runAction('${scenario.key}', 'preview')">Preview</button>
            <button class="ghost" onclick="runAction('${scenario.key}', 'check_prereqs')">Check prereqs</button>
            <button class="warn" onclick="runAction('${scenario.key}', 'execute')">Execute</button>
            <button class="ghost" onclick="runAction('${scenario.key}', 'cleanup')">Cleanup</button>
            <button class="ghost" onclick="runAction('${scenario.key}', 'emit_telemetry')">Emit telemetry</button>
          </div>
        </section>
      `).join("");
    }

    function renderHistory(entries) {
      const el = document.getElementById("history");
      if (!entries.length) {
        el.textContent = "No runs recorded yet.";
        return;
      }
      el.textContent = entries.map((entry) => (
        `${entry.ts} | ${entry.scenario} | ${entry.action} | rc=${entry.returncode}\n${entry.summary}\n`
      )).join("\n");
    }

    async function refresh() {
      state = await getJson("/api/state");
      renderStatus(state.status);
      renderScenarios(state);
      renderHistory(state.history);
    }

    async function runAction(scenario, action) {
      const output = document.getElementById("output");
      output.textContent = `Running ${action} for ${scenario}...`;
      try {
        const result = await getJson(`/api/run?scenario=${encodeURIComponent(scenario)}&action=${encodeURIComponent(action)}`, { method: "POST" });
        output.textContent = JSON.stringify(result, null, 2);
        await refresh();
      } catch (error) {
        output.textContent = String(error.message || error);
        await refresh();
      }
    }

    refresh().catch((error) => {
      document.getElementById("output").textContent = String(error.message || error);
    });
  </script>
</body>
</html>
"""


@dataclass
class LabConfig:
    repo_root: Path
    host: str
    port: int
    token: str
    remote_enabled: bool


def load_env_file(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.exists():
        return values
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip()
    return values


def merge_env(repo_root: Path) -> dict[str, str]:
    merged: dict[str, str] = {}
    for name in [".env", ".env.production", ".env.atomic"]:
        merged.update(load_env_file(repo_root / name))
    return merged


def scenario_env_name(scenario: str) -> str:
    return f"ATOMIC_TESTS_{scenario.upper().replace('-', '_')}"


def configured_tests(env: dict[str, str], scenario: str) -> list[int]:
    value = env.get(scenario_env_name(scenario), "").strip()
    if not value:
        return []
    return [int(part.strip()) for part in value.split(",") if part.strip()]


def state_dir() -> Path:
    if os.name == "nt":
        base = Path(os.getenv("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
        target = base / "AegisCore" / "adversary-lab"
    else:
        target = Path.home() / ".local" / "state" / "aegiscore" / "adversary-lab"
    target.mkdir(parents=True, exist_ok=True)
    return target


def history_path() -> Path:
    return state_dir() / "run-history.jsonl"


def load_history(limit: int = 12) -> list[dict[str, Any]]:
    path = history_path()
    if not path.exists():
        return []
    lines = path.read_text(encoding="utf-8").splitlines()
    entries = [json.loads(line) for line in lines if line.strip()]
    return list(reversed(entries[-limit:]))


def append_history(entry: dict[str, Any]) -> None:
    path = history_path()
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(entry) + "\n")


def powershell_runtime() -> str:
    return shutil.which("pwsh") or shutil.which("powershell.exe") or shutil.which("powershell") or ""


def invoke_atomic(repo_root: Path, scenario: str, action: str) -> dict[str, Any]:
    env = merge_env(repo_root)
    ps = powershell_runtime()
    if not ps:
        raise RuntimeError("PowerShell runtime not found. Install pwsh or powershell.exe.")

    if scenario not in SCENARIOS:
        raise RuntimeError(f"Unknown scenario: {scenario}")
    if action not in ACTION_MAP:
        raise RuntimeError(f"Unknown action: {action}")

    script = repo_root / "tools" / "atomic-red-team" / "Invoke-AgenticAtomic.ps1"
    mode = ACTION_MAP[action]
    command = [ps, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(script), "-Scenario", scenario, "-Mode", mode]

    atomic_path = env.get("ATOMIC_RED_TEAM_PATH", "").strip()
    if atomic_path:
        command.extend(["-AtomicRedTeamPath", atomic_path])

    tests = configured_tests(env, scenario)
    if action in {"check_prereqs", "cleanup"} and tests:
        command.append("-TestNumbers")
        command.extend(str(test) for test in tests)
    if action == "execute":
        if env.get("ATOMIC_REAL_ATTACKS_ENABLED", "").lower() != "true":
            raise RuntimeError("Execution blocked: set ATOMIC_REAL_ATTACKS_ENABLED=true in .env.atomic.")
        if not tests:
            raise RuntimeError(f"Execution blocked: add explicit test numbers to {scenario_env_name(scenario)} in .env.atomic.")
        command.append("-TestNumbers")
        command.extend(str(test) for test in tests)
        command.append("-IUnderstandRisks")

    completed = subprocess.run(
        command,
        cwd=str(repo_root),
        capture_output=True,
        text=True,
        timeout=600,
        check=False,
    )
    payload = {
        "scenario": scenario,
        "action": action,
        "mode": mode,
        "returncode": completed.returncode,
        "stdout": completed.stdout,
        "stderr": completed.stderr,
        "configured_tests": tests,
    }
    summary = completed.stdout.strip() or completed.stderr.strip() or f"{action} finished with return code {completed.returncode}."
    append_history(
        {
            "ts": datetime.now(UTC).isoformat(),
            "scenario": scenario,
            "action": action,
            "returncode": completed.returncode,
            "summary": summary[:800],
        }
    )
    return payload


def build_state(repo_root: Path) -> dict[str, Any]:
    env = merge_env(repo_root)
    return {
        "status": {
            "atomic_default_mode": env.get("ATOMIC_DEFAULT_MODE", "Preview"),
            "atomic_real_attacks_enabled": env.get("ATOMIC_REAL_ATTACKS_ENABLED", "false").lower() == "true",
            "atomic_red_team_path": env.get("ATOMIC_RED_TEAM_PATH", ""),
            "powershell": powershell_runtime(),
            "history_path": str(history_path()),
        },
        "scenarios": [
            {
                "key": key,
                "title": value["title"],
                "technique": value["technique"],
                "summary": value["summary"],
                "configured_tests": ",".join(str(test) for test in configured_tests(env, key)),
            }
            for key, value in SCENARIOS.items()
        ],
        "history": load_history(),
    }


class AdversaryLabHandler(BaseHTTPRequestHandler):
    server_version = "AegisCoreAdversaryLab/0.1"

    @property
    def config(self) -> LabConfig:
        return self.server.config  # type: ignore[attr-defined]

    def log_message(self, fmt: str, *args: object) -> None:
        sys.stdout.write("[aegiscore-adversary-lab] " + fmt % args + "\n")

    def send_json(self, status: HTTPStatus, payload: dict[str, Any]) -> None:
        encoded = json.dumps(payload, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(encoded)

    def send_text(self, status: HTTPStatus, body: str, content_type: str = "text/html") -> None:
        encoded = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", f"{content_type}; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(encoded)

    def authorized(self, query: dict[str, list[str]]) -> bool:
        if not self.config.remote_enabled:
            return True
        supplied = query.get("token", [""])[0]
        return bool(supplied) and secrets.compare_digest(supplied, self.config.token)

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        query = parse_qs(parsed.query)
        if not self.authorized(query):
            self.send_json(HTTPStatus.UNAUTHORIZED, {"error": "invalid token"})
            return
        if parsed.path == "/":
            self.send_text(HTTPStatus.OK, PAGE)
            return
        if parsed.path == "/api/state":
            self.send_json(HTTPStatus.OK, build_state(self.config.repo_root))
            return
        self.send_json(HTTPStatus.NOT_FOUND, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        query = parse_qs(parsed.query)
        if not self.authorized(query):
            self.send_json(HTTPStatus.UNAUTHORIZED, {"error": "invalid token"})
            return
        if parsed.path != "/api/run":
            self.send_json(HTTPStatus.NOT_FOUND, {"error": "not found"})
            return
        scenario = query.get("scenario", [""])[0]
        action = query.get("action", [""])[0]
        try:
            payload = invoke_atomic(self.config.repo_root, scenario, action)
        except RuntimeError as exc:
            self.send_json(HTTPStatus.BAD_REQUEST, {"error": str(exc), "state": build_state(self.config.repo_root)})
            return
        except subprocess.TimeoutExpired:
            self.send_json(HTTPStatus.GATEWAY_TIMEOUT, {"error": f"{action} for {scenario} timed out."})
            return
        status = HTTPStatus.OK if payload["returncode"] == 0 else HTTPStatus.BAD_GATEWAY
        payload["state"] = build_state(self.config.repo_root)
        self.send_json(status, payload)


def main() -> int:
    parser = argparse.ArgumentParser(description="AegisCore Atomic Red Team adversary-emulation console.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8105)
    parser.add_argument("--token", default="")
    parser.add_argument("--allow-remote", action="store_true")
    args = parser.parse_args()

    repo_root = Path(__file__).resolve().parents[2]
    token = args.token or secrets.token_urlsafe(18)
    config = LabConfig(
        repo_root=repo_root,
        host=args.host,
        port=args.port,
        token=token,
        remote_enabled=args.allow_remote,
    )

    server = ThreadingHTTPServer((args.host, args.port), AdversaryLabHandler)
    server.config = config  # type: ignore[attr-defined]
    print("[aegiscore-adversary-lab] AegisCore Adversary Lab started.")
    print(f"[aegiscore-adversary-lab] Bind: http://{args.host}:{args.port}")
    if args.allow_remote:
        print(f"[aegiscore-adversary-lab] Remote token: {token}")
        print(f"[aegiscore-adversary-lab] Remote URL: http://<lab-host-ip>:{args.port}/?token={token}")
    else:
        print("[aegiscore-adversary-lab] Local-only mode enabled.")
    server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
