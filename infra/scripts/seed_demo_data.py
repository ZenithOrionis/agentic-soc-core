from __future__ import annotations

from datetime import UTC, datetime, timedelta

from shared.schemas import Asset, AttackMapping, Incident, NormalizedEvent, Observable, TimelineEntry
from shared.utils.storage import Store


def main() -> None:
    store = Store()
    now = datetime.now(UTC)
    seeds = [
        ("Historical demo C2-like beacon from workstation-2", "high", 0.94, "workstation-2", ["c2", "beacon", "network"]),
        ("Historical suspicious script on workstation-1", "high", 0.82, "workstation-1", ["suspicious-script", "execution"]),
        ("Historical credential abuse against server-1", "critical", 0.96, "server-1", ["credential-access", "bruteforce", "anomalous-success"]),
    ]
    for index, (title, severity, confidence, asset_name, tags) in enumerate(seeds):
        event = NormalizedEvent(
            timestamp=now - timedelta(days=index + 1),
            source="simulator",
            raw_source="seed",
            rule_id=f"seed-{index}",
            rule_name=title,
            severity=severity,  # type: ignore[arg-type]
            confidence=confidence,
            asset=Asset(id=asset_name, hostname=asset_name, container=asset_name),
            observables=[
                Observable(type="hostname", value=asset_name, role="asset"),
                Observable(type="ip", value="203.0.113.50", role="source", reputation="suspicious"),
            ],
            attack=[AttackMapping(tactic="Demo", technique="Seeded historical context", technique_id="DEMO")],
            tags=tags,
            raw={"seed": True, "title": title},
        )
        incident = Incident(
            title=title,
            severity=severity,  # type: ignore[arg-type]
            confidence=confidence,
            asset=event.asset,
            event_ids=[event.id],
            observables=event.observables,
            attack=event.attack,
            correlation_key=f"seed:{asset_name}:{index}",
            timeline=[
                TimelineEntry(timestamp=event.timestamp, kind="seed", summary="Seeded historical incident for demo browsing.", event_id=event.id)
            ],
            metadata={"tags": tags, "seed": True},
        )
        store.add_event(event, incident.correlation_key)
        store.upsert_incident(incident)
    print("Seeded 3 historical incidents.")


if __name__ == "__main__":
    main()

