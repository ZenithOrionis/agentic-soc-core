from __future__ import annotations

import os
from typing import Any

import httpx
from fastapi import FastAPI, HTTPException

from app.normalization import normalize_suricata, normalize_wazuh
from shared.schemas import NormalizedEvent
from shared.utils.logging import configure_logging
from shared.utils.security import auth_headers, install_security_middleware
from shared.utils.storage import Store

logger = configure_logging("normalizer")
app = FastAPI(title="Agentic SOC Normalizer", version="0.1.0")
install_security_middleware(app, "normalizer")
store = Store()
ORCHESTRATOR_URL = os.getenv("ORCHESTRATOR_URL", "http://localhost:8002")


async def publish(event: NormalizedEvent) -> None:
    try:
        async with httpx.AsyncClient(timeout=8.0) as client:
            await client.post(
                f"{ORCHESTRATOR_URL}/events",
                json=event.model_dump(mode="json"),
                headers=auth_headers(),
            )
    except Exception as exc:  # noqa: BLE001
        logger.warning("Could not publish event to orchestrator; event remains queryable locally: %s", exc)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "normalizer"}


@app.get("/events", response_model=list[NormalizedEvent])
def list_events(limit: int = 100) -> list[NormalizedEvent]:
    return store.list_events(limit)


@app.post("/ingest/suricata", response_model=NormalizedEvent)
async def ingest_suricata(payload: dict[str, Any]) -> NormalizedEvent:
    event = normalize_suricata(payload)
    store.add_event(event)
    await publish(event)
    return event


@app.post("/ingest/wazuh", response_model=NormalizedEvent)
async def ingest_wazuh(payload: dict[str, Any]) -> NormalizedEvent:
    event = normalize_wazuh(payload)
    store.add_event(event)
    await publish(event)
    return event


@app.post("/ingest/normalized", response_model=NormalizedEvent)
async def ingest_normalized(payload: NormalizedEvent) -> NormalizedEvent:
    store.add_event(payload)
    await publish(payload)
    return payload


@app.get("/events/{event_id}", response_model=NormalizedEvent)
def get_event(event_id: str) -> NormalizedEvent:
    event = store.get_event(event_id)
    if not event:
        raise HTTPException(status_code=404, detail="event not found")
    return event
