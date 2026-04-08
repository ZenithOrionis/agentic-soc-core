from __future__ import annotations

from typing import Any

import httpx


def post_json(url: str, payload: dict[str, Any], timeout: float = 8.0) -> dict[str, Any]:
    with httpx.Client(timeout=timeout) as client:
        response = client.post(url, json=payload)
        response.raise_for_status()
        return response.json()


def get_json(url: str, timeout: float = 8.0) -> dict[str, Any] | list[dict[str, Any]]:
    with httpx.Client(timeout=timeout) as client:
        response = client.get(url)
        response.raise_for_status()
        return response.json()

