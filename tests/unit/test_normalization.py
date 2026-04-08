import importlib.util
from pathlib import Path


def load_normalization_module():
    module_path = Path("apps/normalizer/app/normalization.py").resolve()
    spec = importlib.util.spec_from_file_location("normalization_under_test", module_path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


def test_suricata_normalization_maps_attack_and_observables() -> None:
    normalization = load_normalization_module()
    event = normalization.normalize_suricata(
        {
            "timestamp": "2026-04-07T12:00:00+00:00",
            "src_ip": "172.24.0.10",
            "dest_ip": "10.13.37.10",
            "host": "workstation-1",
            "alert": {"signature_id": 900001, "signature": "DEMO C2-like repeated outbound beacon", "severity": 2},
        }
    )

    assert event.source == "suricata"
    assert "beacon" in event.tags
    assert event.attack[0].technique_id == "T1071"
    assert any(obs.value == "10.13.37.10" for obs in event.observables)


def test_wazuh_normalization_maps_suspicious_script() -> None:
    normalization = load_normalization_module()
    event = normalization.normalize_wazuh(
        {
            "timestamp": "2026-04-07T12:00:00+00:00",
            "agent": {"name": "workstation-1"},
            "rule": {"id": 100200, "level": 10, "description": "DEMO suspicious encoded shell command pattern"},
            "data": {"username": "demo-user", "process": "bash", "command": "echo ZGVtby | base64 -d"},
        }
    )

    assert event.source == "wazuh"
    assert "suspicious-script" in event.tags
    assert event.attack[0].technique_id == "T1059"

