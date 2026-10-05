"""Correct Ollama client.

This fixes the three defects in vulnhuntr's built-in Ollama client (see
DESIGN.md 9b): it sets num_ctx, places `system` at the top level, and requests
`format: "json"`. These are exactly what made the local 7B model produce
3/3 detections with clean JSON in the Phase 0 benchmark.
"""
from __future__ import annotations

import json
import time
import urllib.request
import urllib.error

from security_agent.ai.base import AIProvider, AIResult


class OllamaProvider(AIProvider):
    name = "ollama"

    def __init__(self, model: str, base_url: str, num_ctx: int = 8192,
                 temperature: float = 0.1, timeout: int = 1800):
        self.model = model
        self.base_url = base_url
        self.num_ctx = num_ctx
        self.temperature = temperature
        self.timeout = timeout

    def generate(self, system: str, prompt: str, *, json: bool = True) -> AIResult:
        import json as _json  # local alias; param name shadows module

        payload = {
            "model": self.model,
            "prompt": prompt,
            "system": system,              # top-level, as /api/generate expects
            "stream": False,
            "options": {
                "temperature": self.temperature,
                "num_ctx": self.num_ctx,   # prevents silent prompt truncation
            },
        }
        if json:
            payload["format"] = "json"     # native structured-output mode

        req = urllib.request.Request(
            self.base_url,
            data=_json.dumps(payload).encode(),
            headers={"Content-Type": "application/json"},
        )

        t0 = time.time()
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                data = _json.loads(resp.read())
        except urllib.error.URLError as e:
            raise ConnectionError(
                f"Ollama request failed ({self.base_url}): {e}. "
                "Is `ollama serve` running and the model pulled?"
            ) from e
        seconds = time.time() - t0

        return AIResult(
            text=data.get("response", ""),
            input_tokens=data.get("prompt_eval_count"),
            output_tokens=data.get("eval_count"),
            seconds=seconds,
        )
