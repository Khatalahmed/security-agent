"""Skill engine (Phase 1 ships one skill: source_audit).

Later phases add a registry/loader/planner and the ported Claude-BugHunter
skill library. For now this package exposes the working local source-audit.
"""
from security_agent.skills.source_audit import run_source_audit

__all__ = ["run_source_audit"]
