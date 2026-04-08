from __future__ import annotations

import os
from datetime import UTC, datetime
from typing import Any

import httpx
from fastapi import FastAPI, HTTPException

from shared.clients import AnalystDecision, OllamaAnalyst
from shared.policy import PolicyEngine
from shared.policy.engine import SEVERITY_BASE, SEVERITY_ORDER
from shared.schemas import Incident, NormalizedEvent, Observable, TimelineEntry
from shared.utils.logging import configure_logging
from shared.utils.security import auth_headers, install_security_middleware
from shared.utils.storage import Store

logger = configure_logging("soc-orchestrator")
app = FastAPI(title="Agentic SOC Orchestrator", version="0.1.0")
install_security_middleware(app, "soc-orchestrator")
store = Store()
policy = PolicyEngine()
ollama_analyst = OllamaAnalyst()
RESPONSE_EXECUTOR_URL = os.getenv("RESPONSE_EXECUTOR_URL", "http://localhost:8003")
OLLAMA_AUTHORITY_MODE = os.getenv("OLLAMA_AUTHORITY_MODE", "advisory").lower()
OLLAMA_AUTHORITY_MIN_CONFIDENCE = float(os.getenv("OLLAMA_AUTHORITY_MIN_CONFIDENCE", "0.80"))
OLLAMA_AUTHORITY_MAX_RISK = os.getenv("OLLAMA_AUTHORITY_MAX_RISK", "medium").lower()
OLLAMA_EXECUTION_USE_APPROVAL_TOKEN = os.getenv("OLLAMA_EXECUTION_USE_APPROVAL_TOKEN", "false").lower() == "true"
OLLAMA_EXECUTION_APPROVAL_TOKEN = os.getenv("RESPONSE_APPROVAL_TOKEN", "")

AI_ACTION_ALLOWLIST = {
    "create_case",
    "attach_observables",
    "run_cortex_analyzer",
    "run_shuffle_workflow",
    "generate_report",
    "collect_artifacts",
    "block_ip",
    "isolate_container",
    "stop_container",
    "kill_process",
}
RISK_ORDER = ["none", "low", "medium", "high"]


def correlation_key(event: NormalizedEvent) -> str:
    tags = set(event.tags)
    src = next((o.value for o in event.observables if o.type == "ip" and o.role == "source"), "unknown-src")
    dst = next((o.value for o in event.observables if o.type == "ip" and o.role == "destination"), "unknown-dst")
    if {"c2", "beacon"}.intersection(tags):
        return f"c2:{event.asset.id}:{dst}"
    if "suspicious-script" in tags:
        return f"script:{event.asset.id}"
    if "bruteforce" in tags or "credential-access" in tags:
        return f"credential:{event.asset.id}:{src}"
    if "exfiltration" in tags:
        return f"exfil:{event.asset.id}:{dst}"
    return f"{event.rule_id}:{event.asset.id}"


def merge_observables(existing: list[Observable], new: list[Observable]) -> list[Observable]:
    merged = {(obs.type, obs.value, obs.role): obs for obs in existing}
    for obs in new:
        merged[(obs.type, obs.value, obs.role)] = obs
    return list(merged.values())


def title_for(event: NormalizedEvent) -> str:
    if "c2" in event.tags:
        return f"C2-like beaconing from {event.asset.hostname}"
    if "suspicious-script" in event.tags:
        return f"Suspicious script execution on {event.asset.hostname}"
    if "bruteforce" in event.tags:
        return f"Credential abuse against {event.asset.hostname}"
    if "exfiltration" in event.tags:
        return f"Exfiltration-like burst from {event.asset.hostname}"
    return f"{event.rule_name} on {event.asset.hostname}"


def action_target(action: str, incident: Incident) -> str:
    if action == "block_ip":
        suspicious = [
            o.value
            for o in incident.observables
            if o.type == "ip" and (o.role in {"destination", "source"} or o.reputation)
        ]
        return suspicious[-1] if suspicious else "unknown-ip"
    if action in {"isolate_container", "stop_container"}:
        return incident.asset.container or incident.asset.hostname
    if action == "kill_process":
        return next((o.value for o in incident.observables if o.type == "process"), "simulated-process")
    if action == "collect_artifacts":
        return incident.asset.id
    if action == "run_cortex_analyzer":
        return ",".join(o.value for o in incident.observables[:5])
    if action == "run_shuffle_workflow":
        return incident.metadata.get("primary_scenario", "generic")
    return incident.id


def guardrail_ai_actions(incident: Incident, requested_actions: list[str]) -> list[str]:
    thresholds = policy.policy["thresholds"]
    approved: list[str] = []
    for action in requested_actions:
        if action not in AI_ACTION_ALLOWLIST:
            continue
        if action in policy.policy.get("irreversible_actions", []):
            continue
        risk = policy.policy.get("action_risk", {}).get(action, "medium")
        if action in {"create_case", "generate_report"} and incident.confidence >= thresholds["case_min"]:
            approved.append(action)
        elif action in {"attach_observables", "run_cortex_analyzer", "run_shuffle_workflow", "collect_artifacts"} and incident.confidence >= thresholds["enrich_min"]:
            approved.append(action)
        elif risk == "low" and incident.confidence >= thresholds["auto_low_risk_min"]:
            approved.append(action)
        elif risk == "medium" and incident.confidence >= thresholds["auto_medium_risk_min"]:
            approved.append(action)
    return list(dict.fromkeys(approved))


def authority_allows_action(action: str, incident: Incident) -> bool:
    if action not in AI_ACTION_ALLOWLIST:
        return False
    if action in policy.policy.get("irreversible_actions", []):
        return False
    if incident.confidence < OLLAMA_AUTHORITY_MIN_CONFIDENCE:
        return False
    risk = policy.policy.get("action_risk", {}).get(action, "medium")
    return RISK_ORDER.index(risk) <= RISK_ORDER.index(OLLAMA_AUTHORITY_MAX_RISK)


def severity_from_confidence(current: str, confidence: float) -> str:
    if confidence >= 0.93:
        return "critical" if current in {"critical", "high"} else "high"
    if confidence >= 0.80 and SEVERITY_ORDER.index(current) < SEVERITY_ORDER.index("high"):
        return "high"
    if confidence < 0.45:
        return "low"
    return current


def merge_ai_decision(
    incident: Incident,
    actions: list[str],
    analyst: AnalystDecision | None,
) -> tuple[list[str], bool]:
    if analyst is None:
        incident.metadata["ollama_analyst"] = {"enabled": ollama_analyst.enabled, "used": False}
        return actions, False

    original_confidence = incident.confidence
    incident.confidence = round(max(0.0, min(0.99, incident.confidence + analyst.confidence_adjustment)), 2)
    incident.severity = severity_from_confidence(incident.severity, incident.confidence)  # type: ignore[assignment]
    ai_actions = guardrail_ai_actions(incident, analyst.recommended_actions)
    selected_actions = list(dict.fromkeys([*actions, *ai_actions]))
    authoritative = False

    if OLLAMA_AUTHORITY_MODE in {"bounded", "direct-lab"}:
        authoritative_actions = [action for action in analyst.recommended_actions if authority_allows_action(action, incident)]
        if authoritative_actions:
            authoritative = True
            selected_actions = list(dict.fromkeys(authoritative_actions))
            if incident.decision:
                incident.decision.selected = f"ollama:{analyst.disposition}:authoritative"
                incident.decision.auto_approved = True
                incident.decision.action_risk = max(
                    (
                        policy.policy.get("action_risk", {}).get(action, "medium")
                        for action in selected_actions
                    ),
                    key=lambda risk: RISK_ORDER.index(risk),
                    default="none",
                )
                incident.decision.rationale.append(
                    f"Ollama authority mode {OLLAMA_AUTHORITY_MODE} selected primary actions: {', '.join(selected_actions)}."
                )

    if analyst.disposition == "suppress" and original_confidence < 0.75:
        selected_actions = []
    elif analyst.disposition in {"case", "escalate"} and incident.confidence >= policy.policy["thresholds"]["case_min"]:
        selected_actions = list(dict.fromkeys([*selected_actions, "create_case", "generate_report"]))
    elif analyst.disposition == "enrich" and incident.confidence >= policy.policy["thresholds"]["enrich_min"]:
        selected_actions = list(dict.fromkeys([*selected_actions, "attach_observables", "run_cortex_analyzer"]))

    if incident.decision:
        incident.decision.selected = f"ollama:{analyst.disposition}"
        incident.decision.confidence = incident.confidence
        incident.decision.rationale.extend([f"Ollama analyst: {item}" for item in analyst.rationale])
        incident.decision.alternatives.extend(analyst.hypotheses)

    incident.metadata["ollama_analyst"] = {
        "enabled": True,
        "used": True,
        "model": ollama_analyst.model,
        "authority_mode": OLLAMA_AUTHORITY_MODE,
        "authority_used": authoritative,
        "disposition": analyst.disposition,
        "confidence_adjustment": analyst.confidence_adjustment,
        "recommended_actions": analyst.recommended_actions,
        "approved_ai_actions": ai_actions,
        "rationale": analyst.rationale,
        "hypotheses": analyst.hypotheses,
        "uncertainty": analyst.uncertainty,
        "next_steps": analyst.next_steps,
    }
    incident.timeline.append(
        TimelineEntry(
                kind="ollama_analyst_decision",
            summary=f"Ollama analyst recommended {analyst.disposition}{' and selected executable actions' if authoritative else ''}.",
            details=incident.metadata["ollama_analyst"],
        )
    )
    return selected_actions, authoritative


async def execute_actions(incident: Incident, actions: list[str], ai_authoritative: bool = False) -> None:
    existing = {a.action_type for a in store.list_actions(incident.id)}
    for action in actions:
        if action in existing and action not in {"attach_observables", "generate_report"}:
            continue
        payload: dict[str, Any] = {
            "incident_id": incident.id,
            "action_type": action,
            "target": action_target(action, incident),
            "rationale": incident.decision.rationale if incident.decision else [],
        }
        if ai_authoritative and OLLAMA_EXECUTION_USE_APPROVAL_TOKEN and OLLAMA_EXECUTION_APPROVAL_TOKEN:
            payload["approval_token"] = OLLAMA_EXECUTION_APPROVAL_TOKEN
            payload["rationale"] = [
                f"Ollama authority mode {OLLAMA_AUTHORITY_MODE} selected this action.",
                *payload["rationale"],
            ]
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                response = await client.post(
                    f"{RESPONSE_EXECUTOR_URL}/actions",
                    json=payload,
                    headers=auth_headers(),
                )
                response.raise_for_status()
                logger.info("action executed: %s", response.json().get("id"))
        except Exception as exc:  # noqa: BLE001
            logger.error("action %s failed for incident %s: %s", action, incident.id, exc)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "soc-orchestrator"}


@app.get("/incidents", response_model=list[Incident])
def incidents(limit: int = 100) -> list[Incident]:
    return store.list_incidents(limit)


@app.get("/incidents/{incident_id}", response_model=Incident)
def get_incident(incident_id: str) -> Incident:
    incident = store.get_incident(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="incident not found")
    return incident


@app.post("/events", response_model=Incident)
async def ingest_event(event: NormalizedEvent) -> Incident:
    key = correlation_key(event)
    existing = store.get_incident_by_key(key)
    now = datetime.now(UTC)
    if existing:
        incident = existing
        if event.id not in incident.event_ids:
            incident.event_ids.append(event.id)
        incident.updated_at = now
        incident.observables = merge_observables(incident.observables, event.observables)
        incident.attack = list({a.technique_id: a for a in [*incident.attack, *event.attack]}.values())
        incident.timeline.append(
            TimelineEntry(kind="detection", summary=f"{event.source} detection: {event.rule_name}", event_id=event.id)
        )
    else:
        incident = Incident(
            title=title_for(event),
            severity=event.severity,
            confidence=event.confidence,
            asset=event.asset,
            event_ids=[event.id],
            observables=event.observables,
            attack=event.attack,
            correlation_key=key,
            timeline=[
                TimelineEntry(kind="detection", summary=f"{event.source} detection: {event.rule_name}", event_id=event.id)
            ],
            metadata={"tags": list(event.tags), "primary_scenario": next(iter(event.tags), "generic")},
        )
    incident.metadata["tags"] = sorted(set(incident.metadata.get("tags", [])).union(event.tags))
    score = policy.score(event, incident)
    incident.confidence = score.confidence
    incident.severity = score.severity  # type: ignore[assignment]
    incident.timeline.append(TimelineEntry(kind="scoring", summary="Deterministic confidence score updated.", details={"rationale": score.rationale}))
    plan = policy.plan(incident)
    incident.decision = plan.decision
    actions = plan.actions
    ai_authoritative = False
    try:
        analyst = await ollama_analyst.decide(
            incident,
            event,
            {
                "decision": plan.decision.model_dump(mode="json"),
                "actions": plan.actions,
                "score_floor_by_severity": SEVERITY_BASE,
            },
        )
        actions, ai_authoritative = merge_ai_decision(incident, actions, analyst)
    except Exception as exc:  # noqa: BLE001
        incident.metadata["ollama_analyst"] = {
            "enabled": ollama_analyst.enabled,
            "used": False,
            "error": str(exc),
        }
        incident.timeline.append(
            TimelineEntry(
                kind="ollama_analyst_error",
                summary="Ollama analyst was unavailable or returned an invalid decision; deterministic policy was used.",
                details=incident.metadata["ollama_analyst"],
            )
        )
    if actions:
        incident.status = "contained" if any(a in actions for a in ["block_ip", "isolate_container", "kill_process"]) else "triaged"
    elif incident.decision.selected in {"suppress", "ollama:suppress"}:
        incident.status = "suppressed"
    else:
        incident.status = "triaged"
    incident.timeline.append(TimelineEntry(kind="decision", summary=incident.decision.selected, details={"actions": actions, "rationale": incident.decision.rationale}))
    store.add_event(event, key)
    store.upsert_incident(incident)
    store.add_audit("incident_decision", incident.id, incident.model_dump(mode="json"))
    await execute_actions(incident, actions, ai_authoritative=ai_authoritative)
    return incident
