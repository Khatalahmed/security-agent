"""Configuration loading (config.toml) + scope allowlist parsing.

Pure stdlib: tomllib is built in on Python 3.11+.
"""
from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from pathlib import Path


# ---- defaults (mirror config/config.toml) -------------------------------

_DEFAULTS: dict = {
    "model": {
        "provider": "ollama",
        "name": "qwen2.5-coder:7b",
        "base_url": "http://127.0.0.1:11434/api/generate",
        "num_ctx": 8192,
        "temperature": 0.1,
        "timeout_seconds": 1800,
        "max_tokens": 2048,       # hosted providers only
    },
    "safety": {
        "scope_file": "config/scope.txt",
        "max_rps": 2,
    },
    "audit": {
        "include_globs": ["*.py"],
        "skip_dirs": [".git", ".venv", "venv", "node_modules", "__pycache__", ".work", "tests"],
        "max_file_kb": 48,
        # Taint is the CROSS-FILE engine; same-file source->sink chains are already
        # covered by the per-file source_audit skill, so analyzing them again just
        # spends LLM calls. Skip them by default; --taint-all-chains overrides.
        "taint_cross_file_only": True,
    },
    "skills": {
        "dir": "skills",     # project-root directory of skill definitions
        "enabled": [],       # [] = run every applicable skill; else only these names
    },
    "rag": {
        "enabled": False,    # ground skill prompts with retrieved disclosed-vuln patterns
        "corpus": "knowledge/patterns.jsonl",
        "k": 3,
        "mode": "bm25",      # bm25 (keyword, always works) | semantic (local embeddings)
        "embed_model": "nomic-embed-text",
        "embed_base_url": "http://127.0.0.1:11434/api/embeddings",
        "cache": "knowledge/embeddings.json",
    },
    "storage": {
        "db_path": "data/findings.db",
        "reports_dir": "reports",
        "audit_log": "logs/audit.log",
    },
}


def _merge(base: dict, over: dict) -> dict:
    out = dict(base)
    for k, v in over.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _merge(out[k], v)
        else:
            out[k] = v
    return out


@dataclass
class Config:
    root: Path
    data: dict = field(default_factory=dict)

    # convenience accessors
    @property
    def model(self) -> dict:
        return self.data["model"]

    @property
    def safety(self) -> dict:
        return self.data["safety"]

    @property
    def audit(self) -> dict:
        return self.data["audit"]

    @property
    def storage(self) -> dict:
        return self.data["storage"]

    def path(self, relative: str) -> Path:
        """Resolve a config-relative path against the project root."""
        p = Path(relative)
        return p if p.is_absolute() else (self.root / p)


def load_config(config_path: str | None = None, root: str | None = None) -> Config:
    """Load config.toml, merged over defaults.

    root defaults to the project root (parent of the security_agent package's
    parent), or an explicit root. config_path defaults to <root>/config/config.toml.
    """
    project_root = Path(root).resolve() if root else Path(__file__).resolve().parent.parent
    cfg_file = Path(config_path) if config_path else project_root / "config" / "config.toml"

    data = _DEFAULTS
    if cfg_file.is_file():
        with open(cfg_file, "rb") as fh:
            loaded = tomllib.load(fh)
        data = _merge(_DEFAULTS, loaded)
    return Config(root=project_root, data=data)


# ---- scope allowlist -----------------------------------------------------

def load_scope(scope_file: Path) -> list[str]:
    """Return the list of authorized host entries (comments/blanks stripped)."""
    if not scope_file.is_file():
        return []
    entries: list[str] = []
    for line in scope_file.read_text(encoding="utf-8").splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        entries.append(s.lower())
    return entries
