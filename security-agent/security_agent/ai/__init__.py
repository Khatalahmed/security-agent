"""AI layer: model-independent provider abstraction.

Local (`ollama`) keeps everything on-machine. Hosted providers (`openai`,
`openrouter`, `anthropic`) run skills on a stronger model but send the analyzed
code / evidence to a third-party API — see `provider_is_local` and the CLI notice.
All providers are pure stdlib (urllib); keys come from environment variables.
"""
from security_agent.ai.base import AIProvider, AIResult
from security_agent.ai.ollama import OllamaProvider
from security_agent.ai.openai_compat import OpenAICompatProvider
from security_agent.ai.anthropic import AnthropicProvider

LOCAL_PROVIDERS = {"ollama"}

_DEFAULT_BASE = {
    "openai": "https://api.openai.com/v1",
    "openrouter": "https://openrouter.ai/api/v1",
}
_DEFAULT_KEY_ENV = {
    "openai": "OPENAI_API_KEY",
    "openrouter": "OPENROUTER_API_KEY",
    "anthropic": "ANTHROPIC_API_KEY",
}


def provider_is_local(model_cfg: dict) -> bool:
    return model_cfg.get("provider", "ollama").lower() in LOCAL_PROVIDERS


def make_provider(model_cfg: dict) -> AIProvider:
    """Factory: build a provider from the [model] config block."""
    provider = model_cfg.get("provider", "ollama").lower()
    name = model_cfg["name"]
    temperature = float(model_cfg.get("temperature", 0.1))
    timeout = int(model_cfg.get("timeout_seconds", 1800))
    max_tokens = int(model_cfg.get("max_tokens", 2048))

    if provider == "ollama":
        return OllamaProvider(
            model=name, base_url=model_cfg["base_url"],
            num_ctx=int(model_cfg.get("num_ctx", 8192)),
            temperature=temperature, timeout=timeout,
        )
    if provider in ("openai", "openrouter"):
        base_url = model_cfg.get("base_url") or _DEFAULT_BASE[provider]
        key_env = model_cfg.get("api_key_env") or _DEFAULT_KEY_ENV[provider]
        return OpenAICompatProvider(
            model=name, base_url=base_url, api_key_env=key_env, name=provider,
            temperature=temperature, max_tokens=max_tokens, timeout=timeout,
        )
    if provider == "anthropic":
        key_env = model_cfg.get("api_key_env") or _DEFAULT_KEY_ENV["anthropic"]
        return AnthropicProvider(
            model=name, api_key_env=key_env,
            temperature=temperature, max_tokens=max_tokens, timeout=timeout,
        )
    raise ValueError(
        f"Unknown model provider '{provider}'. "
        "Supported: ollama (local), openai, openrouter, anthropic (hosted)."
    )


__all__ = [
    "AIProvider", "AIResult", "OllamaProvider", "OpenAICompatProvider",
    "AnthropicProvider", "make_provider", "provider_is_local", "LOCAL_PROVIDERS",
]
