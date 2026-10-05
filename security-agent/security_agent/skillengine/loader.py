"""Load a single skill directory into a Skill object.

A skill directory contains:
  manifest.toml          required — machine-readable metadata + system_prompt
  SKILL.md               optional — human methodology (not parsed for behavior)
  schemas/finding.json   optional — output schema for the validator

Pure stdlib (tomllib + json).
"""
from __future__ import annotations

import json
import tomllib
from pathlib import Path

from security_agent.skillengine.base import Skill


class SkillLoadError(Exception):
    pass


def _as_tuple(value) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        return (value,)
    return tuple(str(v) for v in value)


def load_skill(skill_dir: Path) -> Skill:
    manifest = skill_dir / "manifest.toml"
    if not manifest.is_file():
        raise SkillLoadError(f"no manifest.toml in {skill_dir}")

    try:
        with open(manifest, "rb") as fh:
            m = tomllib.load(fh)
    except tomllib.TOMLDecodeError as e:
        raise SkillLoadError(f"invalid manifest.toml in {skill_dir}: {e}") from e

    for required in ("name", "version", "supports", "system_prompt"):
        if required not in m:
            raise SkillLoadError(f"{manifest}: missing required key '{required}'")

    applies = m.get("applies_when", {}) or {}

    schema: dict = {}
    schema_path = skill_dir / "schemas" / "finding.json"
    if schema_path.is_file():
        try:
            schema = json.loads(schema_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as e:
            raise SkillLoadError(f"invalid finding schema in {skill_dir}: {e}") from e

    return Skill(
        name=str(m["name"]),
        version=str(m["version"]),
        category=str(m.get("category", "uncategorized")),
        description=str(m.get("description", "")),
        when_to_use=str(m.get("when_to_use", "")),
        supports=_as_tuple(m.get("supports")),
        requires_tools=_as_tuple(m.get("requires_tools")),
        risk_level=str(m.get("risk_level", "unknown")),
        requires_authorization=bool(m.get("requires_authorization", False)),
        languages=tuple(s.lower() for s in _as_tuple(applies.get("languages"))),
        filename_globs=_as_tuple(applies.get("filename_globs")),
        detects=tuple(s.lower() for s in _as_tuple(m.get("detects"))),
        engine=str(m.get("engine", "per_file")),
        system_prompt=str(m["system_prompt"]).strip(),
        finding_schema=schema,
        path=skill_dir,
    )
