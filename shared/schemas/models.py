from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Literal
from uuid import uuid4

from pydantic import BaseModel, Field


Severity = Literal["informational", "low", "medium", "high", "critical"]
ActionStatus = Literal["planned", "executing", "succeeded", "failed", "skipped"]


def utc_now() -> datetime:
    return datetime.now(UTC)


def new_id(prefix: str) -> str:
    return f"{prefix}-{uuid4().hex[:16]}"


class Observable(BaseModel):
    type: Literal["ip", "domain", "url", "hash", "hostname", "username", "process", "container"]
    value: str
    role: str = "related"
    reputation: str | None = None


class AttackMapping(BaseModel):
    tactic: str
    technique: str
    technique_id: str


class Asset(BaseModel):
    id: str
    hostname: str
    container: str | None = None
    ip: str | None = None
    user: str | None = None
    criticality: Literal["low", "medium", "high"] = "medium"
    tags: list[str] = Field(default_factory=list)


class NormalizedEvent(BaseModel):
    id: str = Field(default_factory=lambda: new_id("evt"))
    timestamp: datetime = Field(default_factory=utc_now)
    source: Literal["suricata", "wazuh", "simulator", "manual"]
    raw_source: str
    rule_id: str
    rule_name: str
    severity: Severity
    confidence: float = Field(ge=0.0, le=1.0)
    asset: Asset
    observables: list[Observable] = Field(default_factory=list)
    attack: list[AttackMapping] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    raw: dict[str, Any] = Field(default_factory=dict)


class TimelineEntry(BaseModel):
    timestamp: datetime = Field(default_factory=utc_now)
    kind: str
    summary: str
    event_id: str | None = None
    action_id: str | None = None
    details: dict[str, Any] = Field(default_factory=dict)


class Decision(BaseModel):
    policy_name: str
    selected: str
    confidence: float
    severity: Severity
    rationale: list[str] = Field(default_factory=list)
    alternatives: list[str] = Field(default_factory=list)
    auto_approved: bool = False
    action_risk: Literal["none", "low", "medium", "high"] = "none"


class Incident(BaseModel):
    id: str = Field(default_factory=lambda: new_id("inc"))
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)
    title: str
    status: Literal["new", "triaged", "contained", "remediated", "suppressed", "closed"] = "new"
    severity: Severity
    confidence: float = Field(ge=0.0, le=1.0)
    asset: Asset
    event_ids: list[str] = Field(default_factory=list)
    observables: list[Observable] = Field(default_factory=list)
    attack: list[AttackMapping] = Field(default_factory=list)
    correlation_key: str
    timeline: list[TimelineEntry] = Field(default_factory=list)
    decision: Decision | None = None
    case_id: str | None = None
    report_pdf: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class ActionRecord(BaseModel):
    id: str = Field(default_factory=lambda: new_id("act"))
    timestamp: datetime = Field(default_factory=utc_now)
    incident_id: str
    action_type: str
    target: str
    status: ActionStatus = "planned"
    mode: Literal["dry-run", "active-demo", "docker-active"] = "dry-run"
    command: str
    result: str = ""
    rollback: str
    rationale: str
    evidence: dict[str, Any] = Field(default_factory=dict)

