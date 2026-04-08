import os
import time

import httpx
import pytest


pytestmark = pytest.mark.e2e


@pytest.mark.skipif(os.getenv("SOC_E2E") != "1", reason="requires running docker compose stack")
def test_three_required_demo_scenarios_end_to_end() -> None:
    for scenario in ["outbound-beacon", "suspicious-script", "bruteforce-success"]:
        response = httpx.post(f"http://localhost:8005/scenarios/{scenario}", timeout=30)
        response.raise_for_status()

    time.sleep(2)
    incidents = httpx.get("http://localhost:8002/incidents", timeout=10).json()
    actions = httpx.get("http://localhost:8003/actions", timeout=10).json()

    assert len(incidents) >= 3
    assert any(action["action_type"] == "block_ip" for action in actions)
    assert any(action["action_type"] == "generate_report" for action in actions)

