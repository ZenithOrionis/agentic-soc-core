# Ollama Analyst Decision Layer

Agentic SOC Core now includes an optional local Ollama analyst. This is the first true local AI component in the system.

## What It Does

When `OLLAMA_ENABLED=true`, the SOC orchestrator sends the current incident, latest normalized event, and deterministic policy plan to Ollama. Ollama returns a strict JSON analyst decision:

```json
{
  "disposition": "suppress|enrich|case|contain|remediate|escalate",
  "confidence_adjustment": 0.0,
  "recommended_actions": ["create_case", "generate_report"],
  "rationale": ["Evidence-backed reason"],
  "hypotheses": ["Possible explanation"],
  "uncertainty": ["Missing context"],
  "next_steps": ["Recommended analyst step"]
}
```

The orchestrator records the Ollama decision in incident metadata and the incident timeline.

## What It Is Allowed To Influence

Ollama can influence:

- triage disposition
- confidence adjustment within `-0.10` to `+0.10`
- recommended actions
- investigation hypotheses
- uncertainty statements
- next-step recommendations
- report content through incident metadata

## Guardrails

Ollama does not bypass policy.

The orchestrator runs Ollama-recommended actions through guardrails before execution:

- unsupported actions are dropped
- irreversible actions are dropped
- low-risk actions still require configured confidence thresholds
- medium-risk actions still require higher thresholds
- production containment/process actions still require `RESPONSE_APPROVAL_TOKEN`
- if Ollama is unavailable or returns invalid JSON, deterministic policy continues

This allows Ollama to behave like an analyst while deterministic policy remains the execution control plane.

## Start With Ollama

Production mode with Ollama:

```powershell
.\soc.cmd prod-ai-up
```

Demo mode with Ollama only:

```powershell
.\soc.cmd ai-up
```

The configured model is:

```env
OLLAMA_MODEL=qwen2.5:3b-instruct
```

Change it in `.env.production` if your workstation has a different model already pulled.

## Where The Code Lives

- Ollama client: `shared/clients/ollama.py`
- Orchestrator integration: `apps/soc-orchestrator/app/main.py`
- Report rendering: `apps/explainability-service/app/templates/report.html`

