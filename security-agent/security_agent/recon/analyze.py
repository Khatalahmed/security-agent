"""LLM analysis step for Mode A: reason over an attack-surface profile.

Keeps the platform principle intact — the probe tools gather evidence; the model
only reasons over that evidence to prioritize/observe. One model call per target.
Best-effort: a model failure never sinks the scan (deterministic findings remain).
"""
from __future__ import annotations

import json

from security_agent.ai.base import AIProvider
from security_agent.findings.models import Finding, State
from security_agent.skillengine.validator import normalize_enums, validate_item


def _parse(raw: str) -> tuple[list[dict], bool]:
    try:
        data = json.loads(raw)
        items = data.get("findings", []) if isinstance(data, dict) else []
        return (items if isinstance(items, list) else []), True
    except Exception:
        return [], False


def run_target_analysis(profile_summary: str, host: str, scan_id: str,
                        provider: AIProvider, skill, start_index: int = 1,
                        on_progress=lambda m: None) -> tuple[list[Finding], dict]:
    """Run one recon-analysis pass over a profile. Returns (findings, stats)."""
    stats = {"json_ok": 0, "json_bad": 0, "schema_invalid": 0, "seconds": 0.0,
             "skill": skill.name, "error": ""}
    prompt = f"Authorized target attack-surface profile:\n\n{profile_summary}"
    try:
        result = provider.generate(skill.system_prompt, prompt, json=True)
    except Exception as e:                     # model/transport failure — stay graceful
        stats["error"] = str(e)
        on_progress(f"  ! recon analysis skipped (model error): {e}")
        return [], stats

    stats["seconds"] = round(result.seconds, 1)
    items, ok = _parse(result.text)
    stats["json_ok" if ok else "json_bad"] = 1
    if not ok:
        on_progress("  ! recon analysis returned non-JSON; skipped")
        return [], stats

    findings: list[Finding] = []
    counter = start_index
    for item in items:
        if not isinstance(item, dict):
            continue
        item = normalize_enums(item, skill.finding_schema)
        if validate_item(item, skill.finding_schema):
            stats["schema_invalid"] += 1
            continue
        fid = f"F-{scan_id}-{counter:03d}"
        counter += 1
        findings.append(Finding(
            id=fid, scan_id=scan_id, source=f"{skill.name}:{provider.name}", target=host,
            vuln_class=str(item.get("vuln_class", "recon observation")),
            severity=str(item.get("severity", "info")),
            confidence=str(item.get("confidence", "")),
            location=str(item.get("location", host)),
            description=str(item.get("why", "")),
            poc=str(item.get("poc_request", "")),
            remediation=str(item.get("remediation", "")),
            state=State.CANDIDATE,
            evidence={"host": host, "skill": skill.name, "raw_item": item,
                      "model_seconds": stats["seconds"]},
        ))
    on_progress(f"  recon analysis: {len(findings)} candidate(s), {stats['seconds']}s")
    return findings, stats
