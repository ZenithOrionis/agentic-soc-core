from shared.policy import PolicyEngine
from shared.schemas import Asset, Incident, NormalizedEvent, Observable


def test_policy_scores_repeated_known_bad_beacon() -> None:
    engine = PolicyEngine("shared/policy/policy.yaml")
    event = NormalizedEvent(
        source="suricata",
        raw_source="test",
        rule_id="900001",
        rule_name="DEMO C2-like repeated outbound beacon",
        severity="high",
        confidence=0.82,
        asset=Asset(id="workstation-1", hostname="workstation-1"),
        observables=[Observable(type="ip", value="10.13.37.10", role="destination", reputation="known-bad")],
        tags=["c2", "beacon", "network"],
    )
    incident = Incident(
        title="C2-like beaconing",
        severity="high",
        confidence=0.82,
        asset=event.asset,
        event_ids=["evt-1", "evt-2", event.id],
        observables=event.observables,
        correlation_key="c2:workstation-1:10.13.37.10",
        metadata={"tags": event.tags},
    )

    score = engine.score(event, incident)
    plan = engine.plan(incident.model_copy(update={"confidence": score.confidence, "severity": score.severity}))

    assert score.confidence >= 0.9
    assert "block_ip" in plan.actions
    assert "isolate_container" in plan.actions


def test_policy_suppresses_low_confidence_noise() -> None:
    engine = PolicyEngine("shared/policy/policy.yaml")
    incident = Incident(
        title="Low confidence alert",
        severity="low",
        confidence=0.30,
        asset=Asset(id="workstation-1", hostname="workstation-1"),
        correlation_key="noise",
        metadata={"tags": ["noise"]},
    )

    plan = engine.plan(incident)

    assert plan.decision.selected == "suppress"
    assert plan.actions == []

