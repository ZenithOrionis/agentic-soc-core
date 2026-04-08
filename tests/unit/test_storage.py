from shared.schemas import Asset, Incident, NormalizedEvent
from shared.utils.storage import Store


def test_store_round_trips_event_and_incident(tmp_path) -> None:
    store = Store(str(tmp_path / "soc.db"))
    event = NormalizedEvent(
        source="simulator",
        raw_source="unit",
        rule_id="unit-1",
        rule_name="Unit event",
        severity="medium",
        confidence=0.7,
        asset=Asset(id="workstation-1", hostname="workstation-1"),
    )
    incident = Incident(
        title="Unit incident",
        severity="medium",
        confidence=0.7,
        asset=event.asset,
        event_ids=[event.id],
        correlation_key="unit-key",
    )

    store.add_event(event, incident.correlation_key)
    store.upsert_incident(incident)

    assert store.get_event(event.id).rule_id == "unit-1"  # type: ignore[union-attr]
    assert store.get_incident_by_key("unit-key").id == incident.id  # type: ignore[union-attr]

