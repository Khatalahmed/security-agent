"""Skill engine (Phase 2): model-independent registry, loader, planner, validator.

Skill *data* lives in the project-root `skills/` directory (one dir per skill:
manifest.toml + SKILL.md + schemas/). This package is the *code* that discovers,
selects and validates them. Skills never depend on a concrete model backend.
"""
from security_agent.skillengine.base import Context, Skill
from security_agent.skillengine.loader import SkillLoadError, load_skill
from security_agent.skillengine.planner import detect_languages, filter_enabled, plan
from security_agent.skillengine.registry import SkillRegistry
from security_agent.skillengine.validator import is_valid, validate_item

__all__ = [
    "Skill", "Context", "load_skill", "SkillLoadError", "SkillRegistry",
    "plan", "detect_languages", "filter_enabled", "validate_item", "is_valid",
]
