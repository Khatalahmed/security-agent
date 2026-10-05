"""Core types for the skill engine.

A `Skill` is loaded from a skill directory (manifest.toml + SKILL.md +
schemas/finding.json). A `Context` describes what is being assessed, so the
planner can decide which skills apply. Pure stdlib.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


@dataclass(frozen=True)
class Skill:
    name: str
    version: str
    category: str
    description: str
    when_to_use: str
    supports: tuple[str, ...]          # e.g. ("source_audit",) | ("target_scan",)
    requires_tools: tuple[str, ...]
    risk_level: str                    # safe | low | medium | high
    requires_authorization: bool
    languages: tuple[str, ...]         # applies_when.languages ("" / empty = any)
    filename_globs: tuple[str, ...]
    detects: tuple[str, ...]           # canonical classes this skill targets ([] = broad/all)
    engine: str                        # execution engine: "per_file" (default) | "taint"
    system_prompt: str
    finding_schema: dict               # {} if the skill ships no schema
    path: Path                         # the skill directory

    def applies_to_language(self, lang: str) -> bool:
        return (not self.languages) or (lang.lower() in self.languages)

    def supports_mode(self, mode: str) -> bool:
        return mode in self.supports


@dataclass
class Context:
    """What the planner reasons over. For Mode B this is a repo; for Mode A a
    target host (filled in a later phase)."""
    mode: str                          # "source_audit" | "target_scan"
    languages: set[str] = field(default_factory=set)   # detected, lowercased
    frameworks: set[str] = field(default_factory=set)
    target: str = ""                   # repo path or host, for logging
