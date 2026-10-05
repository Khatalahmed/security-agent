"""Automated validation pass — a skeptical second opinion on a CANDIDATE finding.

The lifecycle (findings/models.py) lets a non-human `validator` actor promote
CANDIDATE -> VALIDATION_PENDING -> VALIDATED, but NOT to FALSE_POSITIVE or
HUMAN_CONFIRMED (human-only). So this step only ever *advances confidence* on
findings it judges credible; it never auto-rejects and never confirms. Weak
findings stay CANDIDATE with the validator's verdict recorded for the human.
"""
from __future__ import annotations

import json

from security_agent.ai.base import AIProvider

_VALID_VERDICTS = {"true_positive", "false_positive", "uncertain"}
# Tolerate common model phrasings so a correct judgement isn't lost to wording.
_ALIASES = {
    "confirm": "true_positive", "true": "true_positive", "yes": "true_positive",
    "vulnerable": "true_positive", "exploitable": "true_positive", "tp": "true_positive",
    "reject": "false_positive", "false": "false_positive", "no": "false_positive",
    "safe": "false_positive", "not_vulnerable": "false_positive",
    "not exploitable": "false_positive", "fp": "false_positive",
}


def build_user_prompt(finding: dict, code_context: str = "") -> str:
    ev = finding.get("evidence") or {}
    lines = [
        "Re-examine this CANDIDATE security finding and decide if it is a credible",
        "true positive or a likely false positive.",
        "",
        f"Class: {finding.get('vuln_class')}",
        f"Severity (claimed): {finding.get('severity')}",
        f"Location: {finding.get('location')}",
        f"Source: {finding.get('source')}",
        f"Why (original): {finding.get('description')}",
    ]
    if finding.get("poc"):
        lines.append(f"PoC (candidate): {finding.get('poc')}")
    if isinstance(ev, dict) and ev.get("chain"):
        lines.append(f"Call chain: {' -> '.join(ev['chain'])}")
    if code_context:
        lines += ["", "Relevant code:", "```", code_context.strip(), "```"]
    return "\n".join(lines)


def parse_verdict(raw: str) -> dict:
    """Parse the model's verdict JSON; default to 'uncertain' on any problem."""
    try:
        data = json.loads(raw)
        v = str(data.get("verdict", "")).lower().strip()
        v = _ALIASES.get(v, v)
        if v not in _VALID_VERDICTS:
            v = "uncertain"
        return {
            "verdict": v,
            "confidence": str(data.get("confidence", "")).lower(),
            "reasoning": str(data.get("reasoning", "")),
        }
    except Exception:
        return {"verdict": "uncertain", "confidence": "", "reasoning": "unparseable verdict"}


def run_validation(finding: dict, provider: AIProvider, skill,
                   code_context: str = "") -> tuple[dict, float]:
    """Return (verdict_dict, seconds). verdict in {confirm, reject, uncertain}."""
    prompt = build_user_prompt(finding, code_context)
    result = provider.generate(skill.system_prompt, prompt, json=True)
    return parse_verdict(result.text), result.seconds
