from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import httpx
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from shared.schemas import ActionRecord
from shared.utils.logging import configure_logging
from shared.utils.security import auth_headers, install_security_middleware, is_production
from shared.utils.storage import Store

logger = configure_logging("response-executor")
app = FastAPI(title="Agentic SOC Response Executor", version="0.1.0")
install_security_middleware(app, "response-executor")
store = Store()
MODE = os.getenv("RESPONSE_MODE", "active-demo")
DOCKER_CONTROL_ENABLED = os.getenv("DOCKER_CONTROL_ENABLED", "false").lower() == "true"
REQUIRE_MANUAL_APPROVAL = os.getenv("REQUIRE_MANUAL_APPROVAL", "auto").lower()
APPROVAL_TOKEN = os.getenv("RESPONSE_APPROVAL_TOKEN", "")
APPROVAL_REQUIRED_ACTIONS = {"block_ip", "isolate_container", "stop_container", "kill_process"}
ADAPTER_URL = os.getenv("INTEGRATION_ADAPTER_URL", "http://localhost:8010")
EXPLAINABILITY_URL = os.getenv("EXPLAINABILITY_URL", "http://localhost:8004")
ARTIFACT_DIR = Path(os.getenv("ARTIFACT_DIR", "/data/artifacts"))


class ActionRequest(BaseModel):
    incident_id: str
    action_type: str
    target: str
    rationale: list[str] = []
    approval_token: str | None = None


def success_action(request: ActionRequest, command: str, result: str, rollback: str, evidence: dict[str, Any] | None = None) -> ActionRecord:
    action = ActionRecord(
        incident_id=request.incident_id,
        action_type=request.action_type,
        target=request.target,
        status="succeeded",
        mode="docker-active" if DOCKER_CONTROL_ENABLED and MODE != "dry-run" else MODE,  # type: ignore[arg-type]
        command=command,
        result=result,
        rollback=rollback,
        rationale="; ".join(request.rationale) or "Selected by deterministic policy engine.",
        evidence=evidence or {},
    )
    store.add_action(action)
    store.add_audit("action", action.id, action.model_dump(mode="json"))
    return action


def skipped_action(request: ActionRequest, reason: str, rollback: str = "No rollback required because the action did not run.") -> ActionRecord:
    action = ActionRecord(
        incident_id=request.incident_id,
        action_type=request.action_type,
        target=request.target,
        status="skipped",
        mode="dry-run",
        command=f"approval gate for {request.action_type}",
        result=reason,
        rollback=rollback,
        rationale="; ".join(request.rationale) or "Selected by deterministic policy engine, blocked by approval gate.",
    )
    store.add_action(action)
    store.add_audit("action_skipped", action.id, action.model_dump(mode="json"))
    return action


def approval_required(action_type: str) -> bool:
    if action_type not in APPROVAL_REQUIRED_ACTIONS:
        return False
    if REQUIRE_MANUAL_APPROVAL == "true":
        return True
    if REQUIRE_MANUAL_APPROVAL == "false":
        return False
    return is_production()


def approved(request: ActionRequest) -> bool:
    return bool(APPROVAL_TOKEN) and request.approval_token == APPROVAL_TOKEN


async def post_adapter(path: str, payload: dict[str, Any]) -> dict[str, Any]:
    async with httpx.AsyncClient(timeout=10.0) as client:
        response = await client.post(f"{ADAPTER_URL}{path}", json=payload, headers=auth_headers())
        response.raise_for_status()
        return response.json()


async def maybe_generate_report(incident_id: str) -> dict[str, Any]:
    async with httpx.AsyncClient(timeout=20.0) as client:
        response = await client.post(
            f"{EXPLAINABILITY_URL}/reports/{incident_id}/generate",
            headers=auth_headers(),
        )
        response.raise_for_status()
        return response.json()


@app.get("/health")
def health() -> dict[str, str | bool]:
    return {
        "status": "ok",
        "service": "response-executor",
        "mode": MODE,
        "docker_control_enabled": DOCKER_CONTROL_ENABLED,
        "production": is_production(),
        "manual_approval": REQUIRE_MANUAL_APPROVAL,
    }


@app.get("/actions", response_model=list[ActionRecord])
def list_actions(incident_id: str | None = None, limit: int = 100) -> list[ActionRecord]:
    return store.list_actions(incident_id, limit)


@app.post("/actions", response_model=ActionRecord)
async def execute_action(request: ActionRequest) -> ActionRecord:
    incident = store.get_incident(request.incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="incident not found")

    if approval_required(request.action_type) and not approved(request):
        return skipped_action(
            request,
            "Production approval gate blocked this containment/process/network action. Provide a valid RESPONSE_APPROVAL_TOKEN through an approved workflow to execute it.",
        )

    if request.action_type == "block_ip":
        store.block_value("ip", request.target, request.incident_id, "Demo policy containment for suspicious network observable.")
        return success_action(
            request,
            command=f"demo-firewall block ip {request.target}",
            result=f"{request.target} added to SOC demo blocklist.",
            rollback=f"Remove {request.target} from blocklist table or run reset.",
        )

    if request.action_type == "isolate_container":
        store.quarantine_asset(incident.asset.id, request.incident_id, "Demo quarantine selected by policy.")
        command = f"demo-network isolate asset {incident.asset.id} target {request.target}"
        result = f"{incident.asset.id} marked isolated on quarantine-segment in demo state."
        if DOCKER_CONTROL_ENABLED and MODE != "dry-run":
            result += " Docker socket enforcement is enabled; label checks would be applied before network changes."
        return success_action(
            request,
            command=command,
            result=result,
            rollback=f"Remove {incident.asset.id} from quarantines table; reconnect demo container to monitored-segment if Docker enforcement was enabled.",
        )

    if request.action_type == "stop_container":
        return success_action(
            request,
            command=f"demo-container stop {request.target}",
            result=f"{request.target} stop requested in demo mode.",
            rollback=f"docker compose up -d {request.target}",
        )

    if request.action_type == "kill_process":
        return success_action(
            request,
            command=f"demo-endpoint kill benign-simulated-process target={request.target}",
            result=f"Benign simulated suspicious process marker for {request.target} killed.",
            rollback="Restart the simulator scenario from the UI or Makefile.",
        )

    if request.action_type == "collect_artifacts":
        artifact_dir = ARTIFACT_DIR / request.incident_id
        artifact_dir.mkdir(parents=True, exist_ok=True)
        artifact_path = artifact_dir / "artifact-summary.json"
        artifact_path.write_text(
            json.dumps(
                {
                    "incident_id": request.incident_id,
                    "asset": incident.asset.model_dump(mode="json"),
                    "event_ids": incident.event_ids,
                    "note": "Demo-safe artifact bundle; no host files were collected.",
                },
                indent=2,
            ),
            encoding="utf-8",
        )
        return success_action(
            request,
            command=f"collect demo artifacts for {request.target}",
            result=f"Artifact summary written to {artifact_path}.",
            rollback=f"Delete {artifact_path} if no longer required.",
            evidence={"artifact_path": str(artifact_path)},
        )

    if request.action_type == "create_case":
        case = await post_adapter(
            "/thehive/cases",
            {
                "incident": incident.model_dump(mode="json"),
                "observables": [o.model_dump(mode="json") for o in incident.observables],
            },
        )
        store.save_case(case["case_id"], request.incident_id, incident.title, case.get("status", "Open"), case)
        incident.case_id = case["case_id"]
        store.upsert_incident(incident)
        return success_action(
            request,
            command="thehive-lite create/update case",
            result=f"Case {case['case_id']} available at {case.get('url')}.",
            rollback="Close the local case record in the TheHive lite adapter.",
            evidence=case,
        )

    if request.action_type == "attach_observables":
        payload = await post_adapter(
            "/thehive/observables",
            {"incident_id": request.incident_id, "observables": [o.model_dump(mode="json") for o in incident.observables]},
        )
        return success_action(
            request,
            command="thehive-lite attach observables",
            result=f"Attached {payload.get('count', 0)} observables.",
            rollback="Remove observables from the local case record.",
            evidence=payload,
        )

    if request.action_type == "run_cortex_analyzer":
        payload = await post_adapter(
            "/cortex/analyze",
            {"incident_id": request.incident_id, "observables": [o.model_dump(mode="json") for o in incident.observables]},
        )
        return success_action(
            request,
            command="cortex-lite run local analyzers",
            result="Local analyzer produced deterministic reputation and context results.",
            rollback="No rollback required; analysis is read-only.",
            evidence=payload,
        )

    if request.action_type == "run_shuffle_workflow":
        payload = await post_adapter(
            f"/shuffle/workflows/{request.target}",
            {"incident_id": request.incident_id, "incident_title": incident.title},
        )
        return success_action(
            request,
            command=f"shuffle-lite workflow {request.target}",
            result=f"Workflow {payload.get('workflow')} executed with status {payload.get('status')}.",
            rollback="No rollback required; workflow actions in lite mode are audit-only.",
            evidence=payload,
        )

    if request.action_type == "generate_report":
        action = ActionRecord(
            incident_id=request.incident_id,
            action_type=request.action_type,
            target=request.target,
            status="executing",
            mode="docker-active" if DOCKER_CONTROL_ENABLED and MODE != "dry-run" else MODE,  # type: ignore[arg-type]
            command="explainability-service generate incident report",
            result="Report generation started.",
            rollback="Delete report files from the reports volume if needed.",
            rationale="; ".join(request.rationale) or "Selected by deterministic policy engine.",
        )
        store.add_action(action)
        payload = await maybe_generate_report(request.incident_id)
        action.status = "succeeded"
        action.result = f"Report generated at {payload.get('pdf_path')}."
        action.evidence = payload
        store.add_action(action)
        store.add_audit("action", action.id, action.model_dump(mode="json"))
        return action

    raise HTTPException(status_code=400, detail=f"unsupported action {request.action_type}")
