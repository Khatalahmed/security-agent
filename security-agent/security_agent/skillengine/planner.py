"""Select which skills to run for a given Context.

DESIGN 9c principle #3: a skill planner, not a bag of scanners. The planner
filters the registry by operating mode and (for source audit) by the languages
actually detected, so a Python repo gets Python skills and nothing irrelevant.

Language detection here is intentionally simple (extension-based); richer
fingerprinting (frameworks, manifests) comes with target mode in a later phase.
"""
from __future__ import annotations

from pathlib import Path

from security_agent.skillengine.base import Context, Skill
from security_agent.skillengine.registry import SkillRegistry

# file extension -> language name (lowercase)
_EXT_LANG = {
    ".py": "python", ".js": "javascript", ".jsx": "javascript",
    ".ts": "typescript", ".tsx": "typescript", ".go": "go",
    ".rb": "ruby", ".php": "php", ".java": "java",
}


def detect_languages(repo: Path, skip_dirs: set[str] | None = None) -> set[str]:
    """Infer languages present in a repo from file extensions."""
    skip = skip_dirs or set()
    langs: set[str] = set()
    for p in repo.rglob("*"):
        if not p.is_file():
            continue
        if any(part in skip for part in p.relative_to(repo).parts):
            continue
        lang = _EXT_LANG.get(p.suffix.lower())
        if lang:
            langs.add(lang)
    return langs


def filter_enabled(skills: list[Skill], enabled: list[str] | None) -> list[Skill]:
    """Keep only skills whose name is in `enabled`. An empty/None list means
    'no restriction' (all applicable skills run). Order is preserved."""
    if not enabled:
        return list(skills)
    allow = set(enabled)
    return [s for s in skills if s.name in allow]


def plan(registry: SkillRegistry, context: Context) -> list[Skill]:
    """Return the skills applicable to this context, ordered deterministically."""
    selected: list[Skill] = []
    for skill in registry.by_support(context.mode):
        if context.mode == "source_audit":
            # language-agnostic skill (no languages declared) always applies;
            # otherwise it must match at least one detected language.
            if skill.languages and not (set(skill.languages) & context.languages):
                continue
        selected.append(skill)
    # stable order: category, then name
    selected.sort(key=lambda s: (s.category, s.name))
    return selected
