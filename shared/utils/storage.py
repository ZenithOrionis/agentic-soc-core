from __future__ import annotations

import json
import os
import sqlite3
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Iterator

from pydantic import BaseModel

from shared.schemas import ActionRecord, Incident, NormalizedEvent


def default_db_path() -> str:
    return os.getenv("SOC_DB_PATH", "./data/soc.db")


def _json_default(value: Any) -> str:
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value)


class Store:
    def __init__(self, db_path: str | None = None) -> None:
        self.db_path = db_path or default_db_path()
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self.init()

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.db_path, timeout=30)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA foreign_keys=ON;")
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def init(self) -> None:
        with self.connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS events (
                  id TEXT PRIMARY KEY,
                  timestamp TEXT NOT NULL,
                  source TEXT NOT NULL,
                  asset_id TEXT NOT NULL,
                  rule_id TEXT NOT NULL,
                  correlation_key TEXT,
                  payload TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS incidents (
                  id TEXT PRIMARY KEY,
                  created_at TEXT NOT NULL,
                  updated_at TEXT NOT NULL,
                  status TEXT NOT NULL,
                  severity TEXT NOT NULL,
                  confidence REAL NOT NULL,
                  correlation_key TEXT UNIQUE NOT NULL,
                  payload TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS actions (
                  id TEXT PRIMARY KEY,
                  timestamp TEXT NOT NULL,
                  incident_id TEXT NOT NULL,
                  action_type TEXT NOT NULL,
                  target TEXT NOT NULL,
                  status TEXT NOT NULL,
                  payload TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS cases (
                  id TEXT PRIMARY KEY,
                  incident_id TEXT NOT NULL,
                  title TEXT NOT NULL,
                  status TEXT NOT NULL,
                  payload TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS audit_records (
                  id TEXT PRIMARY KEY,
                  timestamp TEXT NOT NULL,
                  kind TEXT NOT NULL,
                  ref_id TEXT NOT NULL,
                  payload TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS blocklist (
                  value TEXT PRIMARY KEY,
                  kind TEXT NOT NULL,
                  reason TEXT NOT NULL,
                  incident_id TEXT NOT NULL,
                  created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS quarantines (
                  asset_id TEXT PRIMARY KEY,
                  incident_id TEXT NOT NULL,
                  reason TEXT NOT NULL,
                  created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS reports (
                  incident_id TEXT PRIMARY KEY,
                  html_path TEXT NOT NULL,
                  pdf_path TEXT NOT NULL,
                  json_path TEXT NOT NULL,
                  generated_at TEXT NOT NULL
                );
                """
            )

    @staticmethod
    def dumps(model: BaseModel | dict[str, Any]) -> str:
        if isinstance(model, BaseModel):
            return model.model_dump_json()
        return json.dumps(model, default=_json_default)

    def add_event(self, event: NormalizedEvent, correlation_key: str | None = None) -> None:
        with self.connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO events(id, timestamp, source, asset_id, rule_id, correlation_key, payload)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event.id,
                    event.timestamp.isoformat(),
                    event.source,
                    event.asset.id,
                    event.rule_id,
                    correlation_key,
                    self.dumps(event),
                ),
            )

    def list_events(self, limit: int = 100) -> list[NormalizedEvent]:
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT payload FROM events ORDER BY timestamp DESC LIMIT ?", (limit,)
            ).fetchall()
        return [NormalizedEvent.model_validate_json(row["payload"]) for row in rows]

    def get_event(self, event_id: str) -> NormalizedEvent | None:
        with self.connect() as conn:
            row = conn.execute("SELECT payload FROM events WHERE id=?", (event_id,)).fetchone()
        return NormalizedEvent.model_validate_json(row["payload"]) if row else None

    def upsert_incident(self, incident: Incident) -> None:
        with self.connect() as conn:
            conn.execute(
                """
                INSERT INTO incidents(id, created_at, updated_at, status, severity, confidence, correlation_key, payload)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(correlation_key) DO UPDATE SET
                  updated_at=excluded.updated_at,
                  status=excluded.status,
                  severity=excluded.severity,
                  confidence=excluded.confidence,
                  payload=excluded.payload
                """,
                (
                    incident.id,
                    incident.created_at.isoformat(),
                    incident.updated_at.isoformat(),
                    incident.status,
                    incident.severity,
                    incident.confidence,
                    incident.correlation_key,
                    self.dumps(incident),
                ),
            )

    def get_incident(self, incident_id: str) -> Incident | None:
        with self.connect() as conn:
            row = conn.execute("SELECT payload FROM incidents WHERE id=?", (incident_id,)).fetchone()
        return Incident.model_validate_json(row["payload"]) if row else None

    def get_incident_by_key(self, correlation_key: str) -> Incident | None:
        with self.connect() as conn:
            row = conn.execute(
                "SELECT payload FROM incidents WHERE correlation_key=?", (correlation_key,)
            ).fetchone()
        return Incident.model_validate_json(row["payload"]) if row else None

    def list_incidents(self, limit: int = 100) -> list[Incident]:
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT payload FROM incidents ORDER BY updated_at DESC LIMIT ?", (limit,)
            ).fetchall()
        return [Incident.model_validate_json(row["payload"]) for row in rows]

    def add_action(self, action: ActionRecord) -> None:
        with self.connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO actions(id, timestamp, incident_id, action_type, target, status, payload)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    action.id,
                    action.timestamp.isoformat(),
                    action.incident_id,
                    action.action_type,
                    action.target,
                    action.status,
                    self.dumps(action),
                ),
            )

    def list_actions(self, incident_id: str | None = None, limit: int = 100) -> list[ActionRecord]:
        with self.connect() as conn:
            if incident_id:
                rows = conn.execute(
                    "SELECT payload FROM actions WHERE incident_id=? ORDER BY timestamp DESC LIMIT ?",
                    (incident_id, limit),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT payload FROM actions ORDER BY timestamp DESC LIMIT ?", (limit,)
                ).fetchall()
        return [ActionRecord.model_validate_json(row["payload"]) for row in rows]

    def add_audit(self, kind: str, ref_id: str, payload: dict[str, Any]) -> None:
        audit_id = f"audit-{ref_id}-{int(datetime.now(UTC).timestamp() * 1000)}"
        with self.connect() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO audit_records(id, timestamp, kind, ref_id, payload) VALUES (?, ?, ?, ?, ?)",
                (audit_id, datetime.now(UTC).isoformat(), kind, ref_id, json.dumps(payload, default=_json_default)),
            )

    def block_value(self, kind: str, value: str, incident_id: str, reason: str) -> None:
        with self.connect() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO blocklist(value, kind, reason, incident_id, created_at) VALUES (?, ?, ?, ?, ?)",
                (value, kind, reason, incident_id, datetime.now(UTC).isoformat()),
            )

    def quarantine_asset(self, asset_id: str, incident_id: str, reason: str) -> None:
        with self.connect() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO quarantines(asset_id, incident_id, reason, created_at) VALUES (?, ?, ?, ?)",
                (asset_id, incident_id, reason, datetime.now(UTC).isoformat()),
            )

    def save_case(self, case_id: str, incident_id: str, title: str, status: str, payload: dict[str, Any]) -> None:
        with self.connect() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO cases(id, incident_id, title, status, payload) VALUES (?, ?, ?, ?, ?)",
                (case_id, incident_id, title, status, json.dumps(payload, default=_json_default)),
            )

    def save_report(self, incident_id: str, html_path: str, pdf_path: str, json_path: str) -> None:
        with self.connect() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO reports(incident_id, html_path, pdf_path, json_path, generated_at) VALUES (?, ?, ?, ?, ?)",
                (incident_id, html_path, pdf_path, json_path, datetime.now(UTC).isoformat()),
            )

    def report_for(self, incident_id: str) -> dict[str, str] | None:
        with self.connect() as conn:
            row = conn.execute("SELECT * FROM reports WHERE incident_id=?", (incident_id,)).fetchone()
        return dict(row) if row else None

