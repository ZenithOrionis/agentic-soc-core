from shared.clients.ollama import (
    AGENT_TOOL_DEFINITIONS,
    ActionRecommendationTracker,
    AnalystDecision,
    decision_from_payload,
    extract_json_object,
)


def test_extract_json_object_handles_wrapped_response() -> None:
    payload = """
    Analyst summary:
    ```json
    {"disposition":"case","confidence_adjustment":0.05,"recommended_actions":["create_case"],"rationale":["Bad IP hit"],"hypotheses":["Likely hands-on-keyboard"],"uncertainty":[],"next_steps":["Open a case"]}
    ```
    """

    parsed = extract_json_object(payload)

    assert parsed["disposition"] == "case"
    assert parsed["recommended_actions"] == ["create_case"]


def test_decision_from_payload_merges_langchain_tool_calls() -> None:
    tracker = ActionRecommendationTracker()
    tracker.record(
        next(tool for tool in AGENT_TOOL_DEFINITIONS if tool.tool_name == "explainability_generate_incident_report"),
        "Analyst wants a refreshed report for the incident.",
    )
    tracker.record(
        next(tool for tool in AGENT_TOOL_DEFINITIONS if tool.tool_name == "thehive_create_case"),
        "Confidence is high enough for formal case tracking.",
    )

    decision = decision_from_payload(
        {
            "disposition": "escalate",
            "confidence_adjustment": 0.04,
            "recommended_actions": ["run_cortex_analyzer"],
            "rationale": ["Beaconing pattern is persistent."],
            "hypotheses": ["Possible C2 traffic."],
            "uncertainty": ["Destination ownership is not confirmed."],
            "next_steps": ["Review the enriched observables."],
        },
        tracker,
    )

    assert isinstance(decision, AnalystDecision)
    assert decision.tool_calls == [
        "explainability_generate_incident_report",
        "thehive_create_case",
    ]
    assert decision.tool_call_notes["explainability_generate_incident_report"] == [
        "Analyst wants a refreshed report for the incident."
    ]
    assert decision.selected_tools[0].action_name == "generate_report"
    assert decision.selected_tools[0].provider == "Explainability service"
    assert decision.recommended_actions == [
        "generate_report",
        "create_case",
        "run_cortex_analyzer",
    ]
