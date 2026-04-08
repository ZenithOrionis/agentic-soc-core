from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from fastapi import FastAPI

from shared.utils.security import install_security_middleware
from shared.utils.storage import Store

app = FastAPI(
    title="Agentic SOC Integration Adapters",
    description="Working local adapters for TheHive, Cortex, and Shuffle demo flows.",
    version="0.1.0",
)
install_security_middleware(app, "integration-adapters")
store = Store()


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "integration-adapters"}


@app.get("/thehive")
def thehive_home() -> dict[str, str]:
    return {
        "name": "TheHive lite adapter",
        "mode": "local deterministic case API",
        "swap": "Replace THEHIVE_URL and response executor client with a real TheHive API endpoint.",
    }


@app.post("/thehive/cases")
def create_case(payload: dict[str, Any]) -> dict[str, Any]:
    incident = payload["incident"]
    case_id = f"THL-{incident['id'].split('-')[-1]}"
    case = {
        "case_id": case_id,
        "url": f"http://localhost:8010/thehive/cases/{case_id}",
        "status": "Open",
        "title": incident["title"],
        "severity": incident["severity"],
        "created_at": datetime.now(UTC).isoformat(),
        "observables": payload.get("observables", []),
    }
    store.save_case(case_id, incident["id"], incident["title"], "Open", case)
    return case


@app.get("/thehive/cases/{case_id}")
def get_case(case_id: str) -> dict[str, str]:
    return {"case_id": case_id, "status": "Open", "message": "Case is stored in the shared SQLite state store."}


@app.post("/thehive/observables")
def attach_observables(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "incident_id": payload["incident_id"],
        "count": len(payload.get("observables", [])),
        "status": "attached",
    }


@app.get("/cortex")
def cortex_home() -> dict[str, str]:
    return {"name": "Cortex lite adapter", "mode": "deterministic local analyzer API"}


@app.post("/cortex/analyze")
def cortex_analyze(payload: dict[str, Any]) -> dict[str, Any]:
    observables = payload.get("observables", [])
    results = []
    for obs in observables:
        verdict = "suspicious" if obs.get("reputation") in {"known-bad", "suspicious"} else "unknown"
        results.append(
            {
                "observable": obs,
                "analyzer": "LocalReputationAnalyzer",
                "verdict": verdict,
                "explanation": "Deterministic lookup against the demo local reputation context.",
            }
        )
    return {"incident_id": payload["incident_id"], "status": "completed", "results": results}


@app.get("/shuffle")
def shuffle_home() -> dict[str, str]:
    return {"name": "Shuffle lite adapter", "mode": "local workflow execution log API"}


@app.post("/shuffle/workflows/{workflow}")
def shuffle_workflow(workflow: str, payload: dict[str, Any]) -> dict[str, Any]:
    steps = {
        "c2": ["deduplicate alert", "block destination", "open case", "generate report"],
        "beacon": ["deduplicate alert", "block destination", "open case", "generate report"],
        "suspicious-script": ["collect command context", "kill benign process marker", "open case"],
        "credential-access": ["correlate failures", "block source", "open case"],
        "bruteforce": ["correlate failures", "block source", "open case"],
    }.get(workflow, ["record workflow audit event"])
    return {
        "workflow": workflow,
        "status": "completed",
        "incident_id": payload.get("incident_id"),
        "steps": steps,
        "executed_at": datetime.now(UTC).isoformat(),
    }
