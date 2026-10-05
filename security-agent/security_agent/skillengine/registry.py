"""Discover and index skills under a skills/ root.

A skill is any immediate subdirectory containing a manifest.toml. Malformed
skills are collected as errors rather than aborting discovery, so one broken
skill never hides the rest.
"""
from __future__ import annotations

from pathlib import Path

from security_agent.skillengine.base import Skill
from security_agent.skillengine.loader import SkillLoadError, load_skill


class SkillRegistry:
    def __init__(self, skills: list[Skill], errors: list[tuple[Path, str]]):
        self._by_name: dict[str, Skill] = {s.name: s for s in skills}
        self.errors = errors

    @classmethod
    def discover(cls, root: Path) -> "SkillRegistry":
        skills: list[Skill] = []
        errors: list[tuple[Path, str]] = []
        if root.is_dir():
            for child in sorted(p for p in root.iterdir() if p.is_dir()):
                if not (child / "manifest.toml").is_file():
                    continue
                try:
                    skills.append(load_skill(child))
                except SkillLoadError as e:
                    errors.append((child, str(e)))
        return cls(skills, errors)

    def all(self) -> list[Skill]:
        return list(self._by_name.values())

    def get(self, name: str) -> Skill | None:
        return self._by_name.get(name)

    def by_support(self, mode: str) -> list[Skill]:
        return [s for s in self._by_name.values() if s.supports_mode(mode)]

    def __len__(self) -> int:
        return len(self._by_name)
