"""Finding model + lifecycle state machine (DESIGN.md 9c principle 4).

The human gate is enforced here: the model can only ever push a finding as far
as CANDIDATE/TRIAGED/VALIDATED. The transitions to HUMAN_CONFIRMED and
FALSE_POSITIVE are reserved for an explicit human action via the CLI.
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class State(str, Enum):
    DISCOVERED = "DISCOVERED"
    CANDIDATE = "CANDIDATE"
    TRIAGED = "TRIAGED"
    VALIDATION_PENDING = "VALIDATION_PENDING"
    VALIDATED = "VALIDATED"
    HUMAN_CONFIRMED = "HUMAN_CONFIRMED"     # human only
    FALSE_POSITIVE = "FALSE_POSITIVE"       # human only


# Allowed transitions. Note HUMAN_CONFIRMED / FALSE_POSITIVE are only reachable
# via the explicit human-review commands (confirm/reject), never by a skill.
VALID_TRANSITIONS: dict[State, set[State]] = {
    State.DISCOVERED: {State.CANDIDATE, State.FALSE_POSITIVE},
    State.CANDIDATE: {State.TRIAGED, State.VALIDATION_PENDING, State.FALSE_POSITIVE},
    State.TRIAGED: {State.VALIDATION_PENDING, State.FALSE_POSITIVE},
    State.VALIDATION_PENDING: {State.VALIDATED, State.FALSE_POSITIVE},
    State.VALIDATED: {State.HUMAN_CONFIRMED, State.FALSE_POSITIVE},
    State.HUMAN_CONFIRMED: set(),
    State.FALSE_POSITIVE: set(),
}

# Transitions a human (CLI) may perform.
HUMAN_ONLY_TARGETS = {State.HUMAN_CONFIRMED, State.FALSE_POSITIVE}


@dataclass
class Finding:
    id: str
    scan_id: str
    source: str                 # e.g. "source-audit:ollama"
    target: str                 # repo path / file / host
    vuln_class: str
    severity: str = "unknown"
    confidence: str = ""        # free-form (model's words); never auto-promotes state
    location: str = ""          # file:function or file:line_hint
    description: str = ""
    poc: str = ""
    remediation: str = ""
    state: State = State.CANDIDATE
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    evidence: dict[str, Any] = field(default_factory=dict)

    def to_row(self) -> dict:
        d = asdict(self)
        d["state"] = self.state.value
        return d
