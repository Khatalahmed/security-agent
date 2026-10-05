"""OpenAI-compatible provider (OpenAI, OpenRouter, any /chat/completions API).

Pure stdlib (urllib) — no vendor SDK, so the project keeps its zero-dependency
promise. The API key is read from an environment variable, never stored in
config or passed on the command line.

PRIVACY: using a hosted backend sends the analyzed code / target evidence to a
third-party API — the opposite of the local-Ollama guarantee. The CLI warns when
a non-local provider is selected.
"""
from __future__ import annotations

import json as _json
import os
import time
import urllib.error
import urllib.request

from security_agent.ai.base import AIProvider, AIResult


def build_payload(model: str, system: str, prompt: str, *, json: bool,
                  temperature: float, max_tokens: int) -> dict:
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": prompt},
        ],
        "temperature": temperature,
        "max_tokens": max_tokens,
    }
    if json:
        payload["response_format"] = {"type": "json_object"}
    return payload


def parse_response(data: dict) -> tuple[str, int | None, int | None]:
    choices = data.get("choices") or []
    text = ""
    if choices:
        text = (choices[0].get("message") or {}).get("content", "") or ""
    usage = data.get("usage") or {}
    return text, usage.get("prompt_tokens"), usage.get("completion_tokens")


class OpenAICompatProvider(AIProvider):
    def __init__(self, model: str, base_url: str, api_key_env: str, *,
                 name: str = "openai", temperature: float = 0.1,
                 max_tokens: int = 2048, timeout: int = 120,
                 extra_headers: dict | None = None):
        self.name = name
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.temperature = temperature
        self.max_tokens = max_tokens
        self.timeout = timeout
        self.extra_headers = extra_headers or {}
        self.api_key = os.environ.get(api_key_env, "")
        if not self.api_key:
            raise ValueError(
                f"{name}: environment variable {api_key_env} is not set. "
                f"Export your API key, e.g. `export {api_key_env}=...`."
            )

    def generate(self, system: str, prompt: str, *, json: bool = True) -> AIResult:
        payload = build_payload(self.model, system, prompt, json=json,
                                temperature=self.temperature, max_tokens=self.max_tokens)
        headers = {"Content-Type": "application/json",
                   "Authorization": f"Bearer {self.api_key}"}
        headers.update(self.extra_headers)
        req = urllib.request.Request(
            f"{self.base_url}/chat/completions",
            data=_json.dumps(payload).encode(), headers=headers)
        t0 = time.time()
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                data = _json.loads(resp.read())
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", errors="replace")[:500]
            raise ConnectionError(f"{self.name} API HTTP {e.code}: {body}") from e
        except urllib.error.URLError as e:
            raise ConnectionError(f"{self.name} API request failed: {e}") from e
        seconds = time.time() - t0
        text, in_tok, out_tok = parse_response(data)
        return AIResult(text=text, input_tokens=in_tok, output_tokens=out_tok, seconds=seconds)
