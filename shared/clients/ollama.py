from __future__ import annotations

import asyncio
import json
import os
from dataclasses import dataclass, field
from typing import Any, Literal

import httpx
from pydantic import BaseModel, Field, ValidationError

from shared.schemas import Incident, NormalizedEvent

try:
    from langchain.agents import create_agent
    from langchain.tools import tool
    from langchain_ollama import ChatOllama
except ImportError:  # pragma: no cover - exercised indirectly when deps are missing
    ChatOllama = None
    create_agent = None
    tool = None


Disposition = Literal["suppress", "enrich", "case", "contain", "remediate", "escalate"]
SupportedAction = Literal[
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
]

@dataclass(frozen=True)
class AgentToolDefinition:
    tool_name: str
    action_name: SupportedAction
    title: str
    provider: str
    category: str
    description: str


class AgentToolSelection(BaseModel):
    tool_name: str
    action_name: str
    title: str
    provider: str
    category: str
    description: str
    justifications: list[str] = Field(default_factory=list)


AGENT_TOOL_DEFINITIONS: tuple[AgentToolDefinition, ...] = (
    AgentToolDefinition(
        tool_name="thehive_create_case",
        action_name="create_case",
        title="Create or refresh TheHive case",
        provider="TheHive lite adapter",
        category="case_management",
        description=(
            "Use when the incident deserves formal case tracking. This asks the response layer to create or refresh "
            "the case record in the TheHive adapter and preserve the incident as a tracked investigation."
        ),
    ),
    AgentToolDefinition(
        tool_name="thehive_attach_observables",
        action_name="attach_observables",
        title="Attach observables to TheHive case",
        provider="TheHive lite adapter",
        category="case_enrichment",
        description=(
            "Use when the observable set is worth preserving with the case. This attaches IPs, domains, URLs, hashes, "
            "users, or process identifiers so investigators have immediate evidence context."
        ),
    ),
    AgentToolDefinition(
        tool_name="cortex_run_observable_analysis",
        action_name="run_cortex_analyzer",
        title="Run Cortex observable analysis",
        provider="Cortex lite adapter",
        category="enrichment",
        description=(
            "Use when deterministic analyzer output would materially improve triage. This requests the Cortex adapter "
            "to evaluate current observables and add local reputation or context results."
        ),
    ),
    AgentToolDefinition(
        tool_name="shuffle_execute_response_workflow",
        action_name="run_shuffle_workflow",
        title="Execute Shuffle response workflow",
        provider="Shuffle lite adapter",
        category="automation",
        description=(
            "Use when the scenario matches an approved automation workflow. This triggers the Shuffle adapter to run "
            "the mapped workflow steps for the incident and record the execution trace."
        ),
    ),
    AgentToolDefinition(
        tool_name="explainability_generate_incident_report",
        action_name="generate_report",
        title="Generate explainability report",
        provider="Explainability service",
        category="documentation",
        description=(
            "Use when the incident should produce or refresh an HTML and PDF report for analyst review, stakeholder "
            "handoff, or audit evidence."
        ),
    ),
    AgentToolDefinition(
        tool_name="response_collect_artifacts",
        action_name="collect_artifacts",
        title="Collect demo-safe artifacts",
        provider="Response executor",
        category="evidence_collection",
        description=(
            "Use when the incident would benefit from a safe artifact bundle. This records a demo-safe evidence "
            "summary without performing invasive host collection."
        ),
    ),
    AgentToolDefinition(
        tool_name="response_block_ip",
        action_name="block_ip",
        title="Block suspicious IP",
        provider="Response executor",
        category="containment",
        description="Use when a suspicious source or destination IP should be blocked by the bounded response layer.",
    ),
    AgentToolDefinition(
        tool_name="response_isolate_container",
        action_name="isolate_container",
        title="Isolate affected workload",
        provider="Response executor",
        category="containment",
        description="Use when the affected asset or container should be quarantined to limit impact while investigation continues.",
    ),
    AgentToolDefinition(
        tool_name="response_stop_container",
        action_name="stop_container",
        title="Stop suspicious container",
        provider="Response executor",
        category="containment",
        description="Use when a suspicious container should be stopped by the bounded response layer.",
    ),
    AgentToolDefinition(
        tool_name="response_kill_process",
        action_name="kill_process",
        title="Kill suspicious process",
        provider="Response executor",
        category="containment",
        description="Use when a suspicious process should be terminated by the bounded response layer.",
    ),
)

SUPPORTED_ACTIONS: tuple[SupportedAction, ...] = tuple(
    dict.fromkeys(tool_def.action_name for tool_def in AGENT_TOOL_DEFINITIONS)
)


class AnalystDecision(BaseModel):
    disposition: Disposition
    confidence_adjustment: float = Field(default=0.0, ge=-0.10, le=0.10)
    recommended_actions: list[str] = Field(default_factory=list)
    rationale: list[str] = Field(default_factory=list)
    hypotheses: list[str] = Field(default_factory=list)
    uncertainty: list[str] = Field(default_factory=list)
    next_steps: list[str] = Field(default_factory=list)
    tool_calls: list[str] = Field(default_factory=list)
    tool_call_notes: dict[str, list[str]] = Field(default_factory=dict)
    selected_tools: list[AgentToolSelection] = Field(default_factory=list)


@dataclass
class ActionRecommendationTracker:
    selected_actions: list[str] = field(default_factory=list)
    selected_tools: dict[str, AgentToolSelection] = field(default_factory=dict)

    def record(self, tool_def: AgentToolDefinition, justification: str) -> dict[str, Any]:
        note = justification.strip()
        if tool_def.action_name not in self.selected_actions:
            self.selected_actions.append(tool_def.action_name)
        selection = self.selected_tools.get(tool_def.tool_name)
        if selection is None:
            selection = AgentToolSelection(
                tool_name=tool_def.tool_name,
                action_name=tool_def.action_name,
                title=tool_def.title,
                provider=tool_def.provider,
                category=tool_def.category,
                description=tool_def.description,
            )
            self.selected_tools[tool_def.tool_name] = selection
        if note:
            selection.justifications.append(note)
        return {
            "tool_name": tool_def.tool_name,
            "action": tool_def.action_name,
            "provider": tool_def.provider,
            "status": "recorded",
            "selected_actions": self.selected_actions,
            "justification": note or "No justification provided.",
        }


def extract_json_object(text: str) -> dict[str, Any]:
    candidate = text.strip()
    if not candidate:
        raise ValueError("No JSON content returned by analyst.")
    try:
        parsed = json.loads(candidate)
        if isinstance(parsed, dict):
            return parsed
    except json.JSONDecodeError:
        pass
    decoder = json.JSONDecoder()
    for marker in ("{", "["):
        start = candidate.find(marker)
        while start != -1:
            try:
                parsed, _ = decoder.raw_decode(candidate[start:])
            except json.JSONDecodeError:
                start = candidate.find(marker, start + 1)
                continue
            if isinstance(parsed, dict):
                return parsed
            start = candidate.find(marker, start + 1)
    raise ValueError("Analyst response did not contain a valid JSON object.")


def normalize_agent_message_content(content: Any) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        chunks: list[str] = []
        for item in content:
            if isinstance(item, str):
                chunks.append(item)
            elif isinstance(item, dict):
                text = item.get("text") or item.get("content")
                if isinstance(text, str):
                    chunks.append(text)
            else:
                chunks.append(str(item))
        return "\n".join(chunk for chunk in chunks if chunk)
    if content is None:
        return ""
    if isinstance(content, dict):
        return json.dumps(content)
    return str(content)


def decision_from_payload(payload: AnalystDecision | dict[str, Any] | str, tracker: ActionRecommendationTracker) -> AnalystDecision:
    if isinstance(payload, AnalystDecision):
        decision = payload
    else:
        raw = payload if isinstance(payload, dict) else extract_json_object(payload)
        try:
            decision = AnalystDecision.model_validate(raw)
        except ValidationError as exc:
            filtered = {key: value for key, value in raw.items() if key in AnalystDecision.model_fields}
            decision = AnalystDecision.model_validate(filtered)
            if not decision.rationale:
                decision.rationale = [f"Analyst output required normalization: {exc.errors()[0]['msg']}"]

    recommended_actions = list(decision.recommended_actions)
    if tracker.selected_actions:
        recommended_actions = list(dict.fromkeys([*tracker.selected_actions, *recommended_actions]))

    selected_tools = list(tracker.selected_tools.values())
    tool_notes = {tool.tool_name: list(tool.justifications) for tool in selected_tools}
    return decision.model_copy(
        update={
            "recommended_actions": recommended_actions,
            "tool_calls": [tool.tool_name for tool in selected_tools],
            "tool_call_notes": tool_notes,
            "selected_tools": selected_tools,
        }
    )


def action_recommendation_tool(
    tool_def: AgentToolDefinition,
    tracker: ActionRecommendationTracker,
) -> Any:
    if tool is None:
        raise RuntimeError("LangChain tool support is not installed.")

    @tool(tool_def.tool_name, description=tool_def.description)
    def recommend_action(justification: str) -> dict[str, Any]:
        """Record an evidence-backed reason for wanting this bounded SOC action."""

        return tracker.record(tool_def, justification)

    return recommend_action


class OllamaAnalyst:
    def __init__(self) -> None:
        self.enabled = os.getenv("OLLAMA_ENABLED", "false").lower() == "true"
        self.url = os.getenv("OLLAMA_URL", "http://ollama:11434").rstrip("/")
        self.model = os.getenv("OLLAMA_MODEL", "qwen2.5:3b-instruct")
        self.timeout = float(os.getenv("OLLAMA_TIMEOUT_SECONDS", "30"))
        self.temperature = float(os.getenv("OLLAMA_TEMPERATURE", "0.1"))
        self.authority_mode = os.getenv("OLLAMA_AUTHORITY_MODE", "advisory").lower()
        self.agent_mode = os.getenv("OLLAMA_AGENT_MODE", "langchain").lower()

    @property
    def framework(self) -> str:
        return self.agent_mode

    def system_prompt(self) -> str:
        return (
            "You are a senior SOC analyst embedded inside AegisCore. "
            "Use only the evidence provided. Do not invent facts. "
            "You have bounded LangChain tools that represent approved AegisCore, TheHive, Cortex, Shuffle, and report actions. "
            "Call a tool only when you genuinely want AegisCore to recommend that action. "
            "If no action is justified, do not call any tools. "
            "After any tool use, return only valid JSON matching this schema: "
            "{"
            '"disposition":"suppress|enrich|case|contain|remediate|escalate",'
            '"confidence_adjustment": number between -0.10 and 0.10,'
            '"recommended_actions":["create_case|attach_observables|run_cortex_analyzer|run_shuffle_workflow|generate_report|collect_artifacts|block_ip|isolate_container|stop_container|kill_process"],'
            '"rationale":["short evidence-backed reason"],'
            '"hypotheses":["possible explanation"],'
            '"uncertainty":["unknown or missing context"],'
            '"next_steps":["recommended analyst step"]'
            "}. "
            "If you used tools, keep recommended_actions aligned with the tool choices."
        )

    def user_prompt(self, incident: Incident, event: NormalizedEvent, deterministic_plan: dict) -> str:
        payload = {
            "incident": incident.model_dump(mode="json"),
            "latest_event": event.model_dump(mode="json"),
            "deterministic_policy_plan": deterministic_plan,
            "authority_mode": self.authority_mode,
            "agent_mode": self.agent_mode,
            "allowed_dispositions": ["suppress", "enrich", "case", "contain", "remediate", "escalate"],
            "supported_actions": list(SUPPORTED_ACTIONS),
            "available_tools": [
                {
                    "tool_name": tool_def.tool_name,
                    "action_name": tool_def.action_name,
                    "title": tool_def.title,
                    "provider": tool_def.provider,
                    "category": tool_def.category,
                    "description": tool_def.description,
                }
                for tool_def in AGENT_TOOL_DEFINITIONS
            ],
            "safety_note": (
                "Do not recommend destructive actions. Prefer case or enrichment when confidence is uncertain. "
                "If authority_mode is advisory, your actions are recommendations only. "
                "If authority_mode is bounded or direct-lab, choose only necessary actions supported by the evidence."
            ),
        }
        return json.dumps(payload, indent=2)

    def _build_tools(self, tracker: ActionRecommendationTracker) -> list[Any]:
        return [
            action_recommendation_tool(tool_def, tracker)
            for tool_def in AGENT_TOOL_DEFINITIONS
        ]

    async def _invoke_langchain_agent(self, prompt: str, tracker: ActionRecommendationTracker) -> Any:
        if create_agent is None or ChatOllama is None:
            raise RuntimeError(
                "LangChain dependencies are not installed. Install langchain and langchain-ollama in the orchestrator."
            )

        agent = create_agent(
            model=ChatOllama(
                model=self.model,
                base_url=self.url,
                temperature=self.temperature,
            ),
            tools=self._build_tools(tracker),
            system_prompt=self.system_prompt(),
        )
        payload = {"messages": [{"role": "user", "content": prompt}]}
        if hasattr(agent, "ainvoke"):
            return await asyncio.wait_for(agent.ainvoke(payload), timeout=self.timeout)
        return await asyncio.wait_for(asyncio.to_thread(agent.invoke, payload), timeout=self.timeout)

    @staticmethod
    def _extract_final_text(result: Any) -> str:
        if isinstance(result, dict):
            structured = result.get("structured_response")
            if structured is not None:
                return normalize_agent_message_content(structured)
            messages = result.get("messages", [])
        else:
            messages = getattr(result, "messages", [])

        for message in reversed(messages):
            content = getattr(message, "content", None)
            if content is None and isinstance(message, dict):
                content = message.get("content")
            text = normalize_agent_message_content(content)
            if text.strip():
                return text
        raise ValueError("LangChain agent returned no final analyst message.")

    async def _decide_langchain(
        self,
        incident: Incident,
        event: NormalizedEvent,
        deterministic_plan: dict[str, Any],
    ) -> AnalystDecision:
        tracker = ActionRecommendationTracker()
        result = await self._invoke_langchain_agent(self.user_prompt(incident, event, deterministic_plan), tracker)
        if isinstance(result, dict) and result.get("structured_response") is not None:
            return decision_from_payload(result["structured_response"], tracker)
        return decision_from_payload(self._extract_final_text(result), tracker)

    async def _decide_json_direct(
        self,
        incident: Incident,
        event: NormalizedEvent,
        deterministic_plan: dict[str, Any],
    ) -> AnalystDecision:
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
        return decision_from_payload(content, ActionRecommendationTracker())

    async def decide(
        self,
        incident: Incident,
        event: NormalizedEvent,
        deterministic_plan: dict[str, Any],
    ) -> AnalystDecision | None:
        if not self.enabled:
            return None
        if self.agent_mode == "json-direct":
            return await self._decide_json_direct(incident, event, deterministic_plan)
        return await self._decide_langchain(incident, event, deterministic_plan)
