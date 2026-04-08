from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from shared.schemas import Decision, Incident, NormalizedEvent


SEVERITY_BASE = {
    "informational": 0.20,
    "low": 0.35,
    "medium": 0.55,
    "high": 0.75,
    "critical": 0.85,
}

SEVERITY_ORDER = ["informational", "low", "medium", "high", "critical"]


@dataclass
class ScoreResult:
    confidence: float
    severity: str
    rationale: list[str] = field(default_factory=list)


@dataclass
class ActionPlan:
    decision: Decision
    actions: list[str]


class PolicyEngine:
    def __init__(self, policy_file: str | None = None) -> None:
        path = Path(policy_file or os.getenv("POLICY_FILE", "shared/policy/policy.yaml"))
        self.policy: dict[str, Any] = yaml.safe_load(path.read_text(encoding="utf-8"))

    def score(self, event: NormalizedEvent, incident: Incident | None = None) -> ScoreResult:
        reasons: list[str] = []
        score = max(SEVERITY_BASE[event.severity], event.confidence)
        reasons.append(f"Base score {score:.2f} from source severity={event.severity} and event confidence={event.confidence:.2f}.")

        tags = set(event.tags)
        event_count = len(incident.event_ids) if incident else 1
        if event_count >= 3:
            score += 0.12
            reasons.append(f"Repeated sightings boost: {event_count} correlated events.")
        elif event_count >= 2:
            score += 0.07
            reasons.append(f"Repeated sightings boost: {event_count} correlated events.")
        if {"c2", "beacon"}.issubset(tags) and event_count >= 2:
            score += 0.10
            reasons.append("Beacon-pattern boost from repeated C2-like callbacks.")
        if {"suspicious-script", "execution"}.issubset(tags):
            score += 0.08
            reasons.append("Execution-pattern boost for encoded or download-execute command behavior.")
        if any(obs.reputation in {"known-bad", "suspicious"} for obs in event.observables):
            score += 0.08
            reasons.append("Local reputation boost for suspicious observable.")
        if event.source in {"suricata", "wazuh"} and incident and len({e.split(':')[0] for e in incident.event_ids}) > 1:
            score += 0.05
            reasons.append("Multi-source correlation boost.")
        if event.asset.id in self.policy.get("allowlists", {}).get("assets", []):
            score -= 0.25
            reasons.append("Allowlisted asset reduction.")
        if any(obs.value in self.policy.get("allowlists", {}).get("ips", []) for obs in event.observables):
            score -= 0.20
            reasons.append("Allowlisted IP reduction.")

        score = max(0.0, min(0.99, score))
        severity = event.severity
        if score >= 0.93:
            severity = "critical" if event.severity in {"critical", "high"} else "high"
        elif score >= 0.80 and SEVERITY_ORDER.index(event.severity) < SEVERITY_ORDER.index("high"):
            severity = "high"
        elif score < 0.45:
            severity = "low"
        reasons.append(f"Final deterministic confidence={score:.2f}, severity={severity}.")
        return ScoreResult(confidence=round(score, 2), severity=severity, rationale=reasons)

    def plan(self, incident: Incident) -> ActionPlan:
        thresholds = self.policy["thresholds"]
        auto_response = bool(self.policy.get("auto_response_enabled", True))
        tags = set(incident.metadata.get("tags", []))
        matching_rule = None
        for rule_name, rule in self.policy.get("response_rules", {}).items():
            if set(rule.get("match_tags", [])).issubset(tags):
                matching_rule = rule_name
                break

        alternatives = ["suppress", "enrich further", "create/update case", "contain demo asset"]
        if incident.confidence < thresholds["suppress_below"]:
            decision = Decision(
                policy_name=self.policy["name"],
                selected="suppress",
                confidence=incident.confidence,
                severity=incident.severity,
                rationale=["Confidence below suppression threshold; no automated response."],
                alternatives=alternatives,
            )
            return ActionPlan(decision=decision, actions=[])

        requested = self.policy["response_rules"].get(matching_rule or "", {}).get(
            "actions", ["create_case", "generate_report"]
        )
        approved: list[str] = []
        max_risk = "none"
        for action in requested:
            if action in self.policy.get("irreversible_actions", []):
                continue
            risk = self.policy.get("action_risk", {}).get(action, "medium")
            if risk == "low" and incident.confidence >= thresholds["auto_low_risk_min"] and auto_response:
                approved.append(action)
            elif risk == "medium" and incident.confidence >= thresholds["auto_medium_risk_min"] and auto_response:
                approved.append(action)
            elif action in {"create_case", "generate_report"} and incident.confidence >= thresholds["case_min"]:
                approved.append(action)
            elif action in {"attach_observables", "run_cortex_analyzer", "run_shuffle_workflow"} and incident.confidence >= thresholds["enrich_min"]:
                approved.append(action)
            max_risk = risk if ["none", "low", "medium", "high"].index(risk) > ["none", "low", "medium", "high"].index(max_risk) else max_risk

        selected = "automatically contain" if any(a in approved for a in ["block_ip", "isolate_container", "kill_process"]) else "create/update case"
        decision = Decision(
            policy_name=self.policy["name"],
            selected=selected,
            confidence=incident.confidence,
            severity=incident.severity,
            rationale=[
                f"Matched response rule: {matching_rule or 'generic_case'}",
                f"Approved actions under thresholds: {', '.join(approved) if approved else 'none'}",
                "Irreversible actions require manual approval and are not present in this demo plan.",
            ],
            alternatives=alternatives,
            auto_approved=bool(approved),
            action_risk=max_risk,
        )
        return ActionPlan(decision=decision, actions=approved)
