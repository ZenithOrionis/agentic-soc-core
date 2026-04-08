from __future__ import annotations

import argparse
import html
import json
import os
import secrets
import shutil
import subprocess
import sys
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import attack_runner


PAGE = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Agentic SOC Demo Attack Console</title>
  <style>
    :root {{ font-family: system-ui, -apple-system, Segoe UI, sans-serif; background: #07111f; color: #e5f0ff; }}
    body {{ margin: 0; padding: 22px; }}
    header {{ margin-bottom: 22px; }}
    .eyebrow {{ text-transform: uppercase; letter-spacing: .16em; color: #93c5fd; font-weight: 800; font-size: 12px; }}
    h1 {{ margin: 6px 0 8px; font-size: 30px; line-height: 1.05; }}
    p {{ color: #bdd3f4; line-height: 1.45; }}
    .safe {{ background: #052e1b; border: 1px solid #22c55e; color: #bbf7d0; padding: 12px; border-radius: 14px; margin: 14px 0; }}
    .grid {{ display: grid; gap: 12px; }}
    button {{ width: 100%; border: 0; border-radius: 18px; padding: 18px 16px; font-size: 17px; font-weight: 900; color: white; background: linear-gradient(135deg, #2563eb, #7c3aed); box-shadow: 0 14px 30px rgba(0,0,0,.28); }}
    button:active {{ transform: scale(.98); }}
    .secondary {{ background: linear-gradient(135deg, #0f766e, #1d4ed8); }}
    .dangerish {{ background: linear-gradient(135deg, #b45309, #be123c); }}
    #output {{ white-space: pre-wrap; background: #020617; border: 1px solid #1e3a8a; color: #dbeafe; border-radius: 14px; padding: 12px; min-height: 130px; margin-top: 18px; font-size: 12px; overflow: auto; }}
    footer {{ color: #93a4bd; font-size: 12px; margin-top: 22px; }}
  </style>
</head>
<body>
  <header>
    <div class="eyebrow">Safe local demo only</div>
    <h1>Agentic SOC Attack Console</h1>
    <p>Trigger benign adversary-emulation telemetry from your phone. No malware. No exploitation. No destructive commands.</p>
    <div class="safe">Token protected. Backend mode: <strong>{backend}</strong>. Atomic mode still uses your .env.atomic allowlist and explicit test-number controls.</div>
  </header>
  <main class="grid">
    <button onclick="runScenario('outbound-beacon')">C2-Like Beacon</button>
    <button onclick="runScenario('suspicious-script')">Suspicious Script</button>
    <button onclick="runScenario('bruteforce-success')">Brute Force + Success</button>
    <button class="secondary" onclick="runScenario('exfil-burst')">Exfil-Like Burst</button>
    <button class="secondary" onclick="runScenario('persistence-like')">Persistence-Like</button>
    <button class="secondary" onclick="runScenario('suspicious-download')">Suspicious Download</button>
    <button class="dangerish" onclick="runScenario('reverse-shell-like')">Reverse-Shell-Like Callback</button>
    <button onclick="runAll()">Run Core Trio</button>
  </main>
  <pre id="output">Ready. Pick a scenario.</pre>
  <footer>Open the SOC dashboard on the laptop at http://127.0.0.1:8080 to watch incidents and reports.</footer>
  <script>
    const token = new URLSearchParams(window.location.search).get("token") || "";
    async function runScenario(name) {{
      const out = document.getElementById("output");
      out.textContent = "Running " + name + "...";
      const res = await fetch("/run?token=" + encodeURIComponent(token) + "&scenario=" + encodeURIComponent(name), {{method: "POST"}});
      const text = await res.text();
      out.textContent = text;
    }}
    async function runAll() {{
      for (const name of ["outbound-beacon", "suspicious-script", "bruteforce-success"]) {{
        await runScenario(name);
      }}
    }}
  </script>
</body>
</html>
"""


class ConsoleConfig:
    def __init__(
        self,
        token: str,
        normalizer_url: str,
        api_key: str,
        delay: float,
        backend: str,
        repo_root: Path,
    ) -> None:
        self.token = token
        self.normalizer_url = normalizer_url
        self.api_key = api_key
        self.delay = delay
        self.backend = backend
        self.repo_root = repo_root


class MobileAttackHandler(BaseHTTPRequestHandler):
    server_version = "AgenticSOCMobileAttackConsole/0.1"

    @property
    def config(self) -> ConsoleConfig:
        return self.server.config  # type: ignore[attr-defined]

    def log_message(self, fmt: str, *args: object) -> None:
        sys.stdout.write("[mobile-attack-console] " + fmt % args + "\n")

    def send_text(self, status: HTTPStatus, body: str, content_type: str = "text/plain") -> None:
        encoded = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", f"{content_type}; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(encoded)

    def token_valid(self, query: dict[str, list[str]]) -> bool:
        supplied = query.get("token", [""])[0]
        return bool(supplied) and secrets.compare_digest(supplied, self.config.token)

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        query = parse_qs(parsed.query)
        if parsed.path != "/":
            self.send_text(HTTPStatus.NOT_FOUND, "not found")
            return
        if not self.token_valid(query):
            self.send_text(HTTPStatus.UNAUTHORIZED, "invalid token")
            return
        self.send_text(HTTPStatus.OK, PAGE.format(backend=html.escape(self.config.backend)), "text/html")

    def do_POST(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        query = parse_qs(parsed.query)
        if parsed.path != "/run":
            self.send_text(HTTPStatus.NOT_FOUND, "not found")
            return
        if not self.token_valid(query):
            self.send_text(HTTPStatus.UNAUTHORIZED, "invalid token")
            return
        scenario = query.get("scenario", [""])[0]
        if scenario not in attack_runner.SCENARIOS:
            self.send_text(HTTPStatus.BAD_REQUEST, "unknown scenario")
            return

        if self.config.backend == "atomic":
            self.run_atomic_scenario(scenario)
            return

        results: list[dict[str, object]] = []
        try:
            for index, (path, payload) in enumerate(attack_runner.direct_payloads(scenario)):
                payload["timestamp"] = attack_runner.now(index)
                results.append(
                    attack_runner.post_json(
                        f"{self.config.normalizer_url.rstrip('/')}{path}",
                        payload,
                        api_key=self.config.api_key,
                    )
                )
            body = json.dumps(
                {
                    "scenario": scenario,
                    "safe": True,
                    "message": "Benign demo telemetry sent to Agentic SOC Core.",
                    "events": results,
                },
                indent=2,
            )
            self.send_text(HTTPStatus.OK, body, "application/json")
        except SystemExit as exc:
            self.send_text(HTTPStatus.BAD_GATEWAY, html.escape(str(exc)))

    def run_atomic_scenario(self, scenario: str) -> None:
        script = self.config.repo_root / "tools" / "atomic-red-team" / "Invoke-AgenticAtomicDefault.ps1"
        if not script.exists():
            self.send_text(HTTPStatus.INTERNAL_SERVER_ERROR, f"Atomic dispatcher not found: {script}")
            return
        ps_executable = shutil.which("pwsh") or shutil.which("powershell.exe") or shutil.which("powershell")
        if not ps_executable:
            self.send_text(HTTPStatus.INTERNAL_SERVER_ERROR, "PowerShell runtime not found. Install pwsh in the VM.")
            return
        completed = subprocess.run(
            [
                ps_executable,
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                str(script),
                "-Scenario",
                scenario,
            ],
            cwd=str(self.config.repo_root),
            capture_output=True,
            text=True,
            timeout=180,
            check=False,
        )
        body = {
            "scenario": scenario,
            "backend": "atomic",
            "returncode": completed.returncode,
            "stdout": completed.stdout,
            "stderr": completed.stderr,
            "note": "Atomic execution is controlled by .env.atomic. Execute mode requires ATOMIC_REAL_ATTACKS_ENABLED=true and explicit test numbers.",
        }
        status = HTTPStatus.OK if completed.returncode == 0 else HTTPStatus.BAD_GATEWAY
        self.send_text(status, json.dumps(body, indent=2), "application/json")


def main() -> int:
    parser = argparse.ArgumentParser(description="Phone-friendly safe attack console for Agentic SOC Core.")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8099)
    parser.add_argument("--token", default=os.getenv("MOBILE_ATTACK_TOKEN", ""))
    parser.add_argument("--normalizer-url", default=os.getenv("NORMALIZER_URL", "http://127.0.0.1:8001"))
    parser.add_argument("--api-key", default=os.getenv("SOC_API_KEY", ""))
    parser.add_argument("--delay", type=float, default=0.1)
    parser.add_argument("--backend", choices=["telemetry", "atomic"], default=os.getenv("MOBILE_ATTACK_BACKEND", "telemetry"))
    args = parser.parse_args()

    attack_runner.load_env()
    api_key = args.api_key or os.getenv("SOC_API_KEY", "")
    token = args.token or secrets.token_urlsafe(18)
    repo_root = Path(__file__).resolve().parents[2]
    config = ConsoleConfig(
        token=token,
        normalizer_url=args.normalizer_url,
        api_key=api_key,
        delay=args.delay,
        backend=args.backend,
        repo_root=repo_root,
    )

    class ConfiguredServer(ThreadingHTTPServer):
        config = config

    server = ConfiguredServer((args.host, args.port), MobileAttackHandler)
    print("[mobile-attack-console] Safe demo console started.")
    print(f"[mobile-attack-console] Backend: {args.backend}")
    print(f"[mobile-attack-console] Bind: http://{args.host}:{args.port}")
    print("[mobile-attack-console] Open from your phone using the LAN URL printed by the PowerShell launcher.")
    print(f"[mobile-attack-console] Token: {token}")
    server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
