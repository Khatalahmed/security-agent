"""SARIF 2.1.0 export — for CI / code-scanning ingestion (e.g. GitHub).

Maps findings to SARIF results with a rule per vuln class, a severity level, and
a best-effort physical location (file + line when parseable).
"""
from __future__ import annotations

import json
import re
import sqlite3

from security_agent.reporting.json_report import VERSION, finding_to_dict

# severity -> (SARIF level, security-severity 0..10)
_SEV_MAP = {
    "critical": ("error", "9.5"), "high": ("error", "8.0"),
    "medium": ("warning", "5.0"), "low": ("note", "3.0"),
    "info": ("note", "1.0"), "unknown": ("note", "1.0"),
}
_LINE_RE = re.compile(r":(\d+)")


def _rule_id(vuln_class: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", (vuln_class or "finding").lower()).strip("-")
    return slug or "finding"


def _file_and_line(f: dict) -> tuple[str, int | None]:
    ev = f.get("evidence") or {}
    uri = ev.get("file")
    if not uri and isinstance(ev.get("chain"), list) and ev["chain"]:
        uri = ev["chain"][-1].split("::")[0]
    if not uri:
        uri = f.get("target") or f.get("location") or "unknown"
    line = None
    m = _LINE_RE.search(f.get("location") or "")
    if m:
        try:
            line = int(m.group(1))
        except ValueError:
            line = None
    return uri, line


def render_sarif(scan_id: str, scan_row: sqlite3.Row | None,
                 findings: list[sqlite3.Row]) -> str:
    dicts = [finding_to_dict(r) for r in findings]

    rules: dict[str, dict] = {}
    results = []
    for f in dicts:
        rid = _rule_id(f["vuln_class"])
        if rid not in rules:
            rules[rid] = {
                "id": rid,
                "name": f["vuln_class"] or "Finding",
                "shortDescription": {"text": f["vuln_class"] or "Finding"},
            }
        level, sec = _SEV_MAP.get((f["severity"] or "unknown").lower(), ("note", "1.0"))
        uri, line = _file_and_line(f)
        region = {"startLine": line} if line else {}
        phys = {"artifactLocation": {"uri": uri}}
        if region:
            phys["region"] = region
        results.append({
            "ruleId": rid,
            "level": level,
            "message": {"text": (f["description"] or f["vuln_class"] or "finding")
                        + f"  [state: {f['state']}; source: {f['source']}]"},
            "locations": [{"physicalLocation": phys}],
            "properties": {
                "security-severity": sec,
                "state": f["state"], "confidence": f["confidence"],
                "source": f["source"], "finding_id": f["id"],
                "candidate": True,
            },
        })

    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "security-agent",
                "version": VERSION,
                "informationUri": "https://localhost/security-agent",
                "rules": list(rules.values()),
            }},
            "automationDetails": {"id": scan_id},
            "results": results,
        }],
    }
    return json.dumps(doc, indent=2)
