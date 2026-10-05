"""Machine-readable JSON report.

A stable, self-describing document: scan metadata, a severity/state summary, and
the full finding list (with evidence parsed back from its stored JSON string).
"""
from __future__ import annotations

import json
import sqlite3
from collections import Counter
from datetime import datetime, timezone

TOOL = "security-agent"
VERSION = "0.1.0"

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}


def finding_to_dict(r: sqlite3.Row) -> dict:
    try:
        evidence = json.loads(r["evidence"]) if r["evidence"] else {}
    except Exception:
        evidence = {"_raw": r["evidence"]}
    return {
        "id": r["id"], "scan_id": r["scan_id"], "source": r["source"],
        "target": r["target"], "vuln_class": r["vuln_class"],
        "severity": r["severity"], "confidence": r["confidence"],
        "location": r["location"], "description": r["description"],
        "poc": r["poc"], "remediation": r["remediation"], "state": r["state"],
        "created_at": r["created_at"], "evidence": evidence,
    }


def build_report(scan_id: str, scan_row: sqlite3.Row | None,
                 findings: list[sqlite3.Row]) -> dict:
    ordered = sorted(findings,
                     key=lambda r: _SEV_ORDER.get((r["severity"] or "unknown").lower(), 5))
    scan = None
    if scan_row is not None:
        scan = {"mode": scan_row["mode"], "target": scan_row["target"],
                "model": scan_row["model"], "started_at": scan_row["started_at"]}
    return {
        "tool": TOOL, "version": VERSION, "scan_id": scan_id, "scan": scan,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "disclaimer": "All findings are CANDIDATE until a human confirms them.",
        "summary": {
            "total": len(findings),
            "by_severity": dict(Counter((r["severity"] or "unknown").lower() for r in findings)),
            "by_state": dict(Counter(r["state"] for r in findings)),
        },
        "findings": [finding_to_dict(r) for r in ordered],
    }


def render_json(scan_id: str, scan_row: sqlite3.Row | None,
                findings: list[sqlite3.Row]) -> str:
    return json.dumps(build_report(scan_id, scan_row, findings), indent=2)
