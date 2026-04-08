from shared.policy import PolicyEngine
from shared.schemas import Asset, Incident, NormalizedEvent, Observable


def test_bruteforce_success_becomes_containment_plan() -> None:
    engine = PolicyEngine("shared/policy/policy.yaml")
    asset = Asset(id="server-1", hostname="server-1")
    event = NormalizedEvent(
        source="wazuh",
        raw_source="integration",
        rule_id="100301",
        rule_name="DEMO suspicious login success after brute force",
        severity="high",
        confidence=0.86,
        asset=asset,
        observables=[Observable(type="ip", value="203.0.113.50", role="source", reputation="suspicious")],
        tags=["credential-access", "bruteforce", "anomalous-success"],
    )
    incident = Incident(
        title="Credential abuse against server-1",
        severity="high",
        confidence=0.86,
        asset=asset,
        event_ids=["evt-a", "evt-b", "evt-c", event.id],
        observables=event.observables,
        correlation_key="credential:server-1:203.0.113.50",
        metadata={"tags": event.tags},
    )

    score = engine.score(event, incident)
    incident.confidence = score.confidence
    plan = engine.plan(incident)

    assert score.confidence >= 0.9
    assert "block_ip" in plan.actions
    assert "create_case" in plan.actions

