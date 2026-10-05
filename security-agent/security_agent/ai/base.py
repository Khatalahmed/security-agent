"""Provider-independent interface. Skills depend on this, never on a concrete
backend — so swapping Ollama for a hosted model later changes nothing upstream.
"""
from __future__ import annotations

import abc
from dataclasses import dataclass


@dataclass
class AIResult:
    text: str                 # raw model output (expected to be JSON when json=True)
    input_tokens: int | None
    output_tokens: int | None
    seconds: float


class AIProvider(abc.ABC):
    name: str

    @abc.abstractmethod
    def generate(self, system: str, prompt: str, *, json: bool = True) -> AIResult:
        """Run one completion. When json=True the provider must request
        structured/JSON output from the backend."""
        raise NotImplementedError
