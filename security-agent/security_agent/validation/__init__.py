"""Automated validation: a skeptical second-opinion pass over candidate findings."""
from security_agent.validation.validator import (
    build_user_prompt, parse_verdict, run_validation,
)

__all__ = ["build_user_prompt", "parse_verdict", "run_validation"]
