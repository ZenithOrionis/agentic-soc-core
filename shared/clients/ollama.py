from __future__ import annotations

import json
import os
from typing import Literal

import httpx
from pydantic import BaseModel, Field, ValidationError

from shared.schemas import Incident, NormalizedEvent


Disposition = Literal["suppress", "enrich", "case", "contain", "remediate", "escalate"]


class AnalystDecision(BaseModel):
    disposition: Disposition
    confidence_adjustment: float = Field(default=0.0, ge=-0.10, le=0.10)
    recommended_actions: list[str] = Field(default_factory=list)
    rationale: list[str] = Field(default_factory=list)
    hypotheses: list[str] = Field(default_factory=list)
    uncertainty: list[str] = Field(default_factory=list)
    next_steps: list[str] = Field(default_factory=list)


class OllamaAnalyst:
    def __init__(self) -> None:
        self.enabled = os.getenv("OLLAMA_ENABLED", "false").lower() == "true"
        self.url = os.getenv("OLLAMA_URL", "http://ollama:11434").rstrip("/")
        self.model = os.getenv("OLLAMA_MODEL", "qwen2.5:3b-instruct")
        self.timeout = float(os.getenv("OLLAMA_TIMEOUT_SECONDS", "30"))
        self.temperature = float(os.getenv("OLLAMA_TEMPERATURE", "0.1"))
        self.authority_mode = os.getenv("OLLAMA_AUTHORITY_MODE", "advisory").lower()

    def system_prompt(self) -> str:
        return (
            "You are a senior SOC analyst embedded inside Agentic SOC Core. "
            "You must make analyst-style triage decisions using only the evidence provided. "
            "You are not allowed to invent evidence. "
            "Return only valid JSON matching this schema: "
            "{"
            '"disposition":"suppress|enrich|case|contain|remediate|escalate",'
            '"confidence_adjustment": number between -0.10 and 0.10,'
            '"recommended_actions":["create_case|attach_observables|run_cortex_analyzer|run_shuffle_workflow|generate_report|collect_artifacts|block_ip|isolate_container|stop_container|kill_process"],'
            '"rationale":["short evidence-backed reason"],'
            '"hypotheses":["possible explanation"],'
            '"uncertainty":["unknown or missing context"],'
            '"next_steps":["recommended analyst step"]'
            "}."
        )

    def user_prompt(self, incident: Incident, event: NormalizedEvent, deterministic_plan: dict) -> str:
        payload = {
            "incident": incident.model_dump(mode="json"),
            "latest_event": event.model_dump(mode="json"),
            "deterministic_policy_plan": deterministic_plan,
            "authority_mode": self.authority_mode,
            "allowed_dispositions": ["suppress", "enrich", "case", "contain", "remediate", "escalate"],
            "safety_note": "Do not recommend destructive actions. Prefer case/enrichment when confidence is uncertain. If authority_mode is advisory, your actions are recommendations only. If authority_mode is bounded or direct-lab, choose only necessary actions supported by the evidence.",
        }
        return json.dumps(payload, indent=2)

    async def decide(
        self,
        incident: Incident,
        event: NormalizedEvent,
        deterministic_plan: dict,
    ) -> AnalystDecision | None:
        if not self.enabled:
            return None
        request = {
            "model": self.model,
            "stream": False,
            "format": "json",
            "options": {"temperature": self.temperature},
            "messages": [
                {"role": "system", "content": self.system_prompt()},
                {"role": "user", "content": self.user_prompt(incident, event, deterministic_plan)},
            ],
        }
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            response = await client.post(f"{self.url}/api/chat", json=request)
            response.raise_for_status()
        content = response.json().get("message", {}).get("content", "{}")
        try:
            return AnalystDecision.model_validate_json(content)
        except ValidationError:
            return AnalystDecision.model_validate(json.loads(content))
