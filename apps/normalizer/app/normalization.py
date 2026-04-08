from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from shared.schemas import Asset, AttackMapping, NormalizedEvent, Observable


SURICATA_RULE_MAP = {
    "900001": {
        "tags": ["c2", "beacon", "network"],
        "attack": [AttackMapping(tactic="Command and Control", technique="Application Layer Protocol", technique_id="T1071")],
    },
    "900004": {
        "tags": ["exfiltration", "network"],
        "attack": [AttackMapping(tactic="Exfiltration", technique="Exfiltration Over Web Service", technique_id="T1567")],
    },
}

WAZUH_RULE_MAP = {
    "100200": {
        "tags": ["suspicious-script", "execution"],
        "attack": [AttackMapping(tactic="Execution", technique="Command and Scripting Interpreter", technique_id="T1059")],
    },
    "100201": {
        "tags": ["suspicious-script", "download", "execution"],
        "attack": [
            AttackMapping(tactic="Execution", technique="Command and Scripting Interpreter", technique_id="T1059"),
            AttackMapping(tactic="Command and Control", technique="Ingress Tool Transfer", technique_id="T1105"),
        ],
    },
    "100202": {
        "tags": ["suspicious-script", "reverse-shell", "execution", "command-and-control"],
        "attack": [
            AttackMapping(tactic="Execution", technique="Command and Scripting Interpreter", technique_id="T1059"),
            AttackMapping(tactic="Command and Control", technique="Application Layer Protocol", technique_id="T1071"),
        ],
    },
    "100300": {
        "tags": ["credential-access", "bruteforce"],
        "attack": [AttackMapping(tactic="Credential Access", technique="Brute Force", technique_id="T1110")],
    },
    "100301": {
        "tags": ["credential-access", "bruteforce", "anomalous-success"],
        "attack": [AttackMapping(tactic="Credential Access", technique="Valid Accounts", technique_id="T1078")],
    },
    "100400": {
        "tags": ["persistence"],
        "attack": [AttackMapping(tactic="Persistence", technique="Boot or Logon Initialization Scripts", technique_id="T1037")],
    },
}


def _parse_ts(value: str | None) -> datetime:
    if not value:
        return datetime.now(UTC)
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _suricata_severity(alert_severity: int | str | None) -> str:
    value = int(alert_severity or 3)
    if value <= 1:
        return "critical"
    if value == 2:
        return "high"
    if value == 3:
        return "medium"
    return "low"


def _wazuh_severity(level: int | str | None) -> str:
    value = int(level or 3)
    if value >= 13:
        return "critical"
    if value >= 10:
        return "high"
    if value >= 6:
        return "medium"
    return "low"


def normalize_suricata(payload: dict[str, Any]) -> NormalizedEvent:
    alert = payload.get("alert", {})
    rule_id = str(alert.get("signature_id", "suricata-unknown"))
    mapped = SURICATA_RULE_MAP.get(rule_id, {"tags": ["network"], "attack": []})
    src_ip = payload.get("src_ip", "unknown")
    dest_ip = payload.get("dest_ip", "unknown")
    asset_name = payload.get("host", payload.get("in_iface", "workstation-1"))
    observables = [
        Observable(type="ip", value=src_ip, role="source", reputation="suspicious" if src_ip.startswith("203.0.113.") else None),
        Observable(type="ip", value=dest_ip, role="destination", reputation="known-bad" if dest_ip in {"10.13.37.10", "203.0.113.50"} else None),
    ]
    if url := payload.get("http", {}).get("url"):
        observables.append(Observable(type="url", value=url, role="request"))
    return NormalizedEvent(
        timestamp=_parse_ts(payload.get("timestamp")),
        source="suricata",
        raw_source="suricata:eve.json",
        rule_id=rule_id,
        rule_name=alert.get("signature", "Suricata alert"),
        severity=_suricata_severity(alert.get("severity")),
        confidence=0.76 if "beacon" in mapped["tags"] else 0.70,
        asset=Asset(
            id=asset_name,
            hostname=asset_name,
            container=payload.get("container", asset_name),
            ip=payload.get("src_ip"),
            criticality="medium",
            tags=["monitored-endpoint"],
        ),
        observables=observables,
        attack=mapped["attack"],
        tags=mapped["tags"],
        raw=payload,
    )


def normalize_wazuh(payload: dict[str, Any]) -> NormalizedEvent:
    rule = payload.get("rule", {})
    agent = payload.get("agent", {})
    data = payload.get("data", {})
    rule_id = str(rule.get("id", "wazuh-unknown"))
    mapped = WAZUH_RULE_MAP.get(rule_id, {"tags": ["host"], "attack": []})
    hostname = agent.get("name", data.get("hostname", "workstation-1"))
    observables: list[Observable] = [
        Observable(type="hostname", value=hostname, role="asset"),
    ]
    if username := data.get("username"):
        observables.append(Observable(type="username", value=username, role="account"))
    if process := data.get("process"):
        observables.append(Observable(type="process", value=process, role="process"))
    if src_ip := data.get("srcip"):
        observables.append(Observable(type="ip", value=src_ip, role="source", reputation="suspicious"))
    if command := data.get("command"):
        observables.append(Observable(type="process", value=command[:200], role="command"))

    return NormalizedEvent(
        timestamp=_parse_ts(payload.get("timestamp")),
        source="wazuh",
        raw_source="wazuh:alerts.json",
        rule_id=rule_id,
        rule_name=rule.get("description", "Wazuh alert"),
        severity=_wazuh_severity(rule.get("level")),
        confidence=0.78 if "anomalous-success" not in mapped["tags"] else 0.86,
        asset=Asset(
            id=hostname,
            hostname=hostname,
            container=data.get("container", hostname),
            ip=data.get("asset_ip"),
            user=data.get("username"),
            criticality="medium",
            tags=["monitored-endpoint"],
        ),
        observables=observables,
        attack=mapped["attack"],
        tags=mapped["tags"],
        raw=payload,
    )
