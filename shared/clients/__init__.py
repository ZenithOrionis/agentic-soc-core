"""HTTP clients for local adapters and replaceable external integrations."""

from .ollama import AnalystDecision, OllamaAnalyst

__all__ = ["AnalystDecision", "OllamaAnalyst"]
