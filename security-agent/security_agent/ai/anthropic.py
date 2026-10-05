"""Anthropic (Claude) provider — pure stdlib (urllib), no SDK.

Uses the Messages API. The key comes from an environment variable. Same PRIVACY
note as the OpenAI-compatible provider: this sends analyzed code off-machine.
"""
from __future__ import annotations

import json as _json
import os
import time
import urllib.error
import urllib.request

from security_agent.ai.base import AIProvider, AIResult

API_URL = "https://api.anthropic.com/v1/messages"
API_VERSION = "2023-06-01"


def build_payload(model: str, system: str, prompt: str, *, json: bool,
                  temperature: float, max_tokens: int) -> dict:
    # Anthropic has no json_object mode; the skills already demand JSON in the
    # system prompt. We reinforce it with a short instruction when json=True.
    sys_text = system
    if json:
        sys_text = system + "\n\nReturn ONLY the JSON object, no prose, no code fences."
    return {
        "model": model,
        "max_tokens": max_tokens,
        "temperature": temperature,
        "system": sys_text,
        "messages": [{"role": "user", "content": prompt}],
    }


def parse_response(data: dict) -> tuple[str, int | None, int | None]:
    blocks = data.get("content") or []
    text = "".join(b.get("text", "") for b in blocks if b.get("type") == "text")
    usage = data.get("usage") or {}
    return text, usage.get("input_tokens"), usage.get("output_tokens")


class AnthropicProvider(AIProvider):
    name = "anthropic"

    def __init__(self, model: str, api_key_env: str = "ANTHROPIC_API_KEY", *,
                 temperature: float = 0.1, max_tokens: int = 2048, timeout: int = 120):
        self.model = model
        self.temperature = temperature
        self.max_tokens = max_tokens
        self.timeout = timeout
        self.api_key = os.environ.get(api_key_env, "")
        if not self.api_key:
            raise ValueError(
                f"anthropic: environment variable {api_key_env} is not set. "
                f"Export your API key, e.g. `export {api_key_env}=...`."
            )

    def generate(self, system: str, prompt: str, *, json: bool = True) -> AIResult:
        payload = build_payload(self.model, system, prompt, json=json,
                                temperature=self.temperature, max_tokens=self.max_tokens)
        headers = {"Content-Type": "application/json", "x-api-key": self.api_key,
                   "anthropic-version": API_VERSION}
        req = urllib.request.Request(API_URL, data=_json.dumps(payload).encode(),
                                     headers=headers)
        t0 = time.time()
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                data = _json.loads(resp.read())
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", errors="replace")[:500]
            raise ConnectionError(f"anthropic API HTTP {e.code}: {body}") from e
        except urllib.error.URLError as e:
            raise ConnectionError(f"anthropic API request failed: {e}") from e
        seconds = time.time() - t0
        text, in_tok, out_tok = parse_response(data)
        return AIResult(text=text, input_tokens=in_tok, output_tokens=out_tok, seconds=seconds)
