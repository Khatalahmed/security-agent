"""Render stored findings into a HackerOne-style Markdown report."""
from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "unknown": 4}


def render_markdown(scan_id: str, scan_row: sqlite3.Row | None,
                    findings: list[sqlite3.Row]) -> str:
    lines: list[str] = []
    lines.append(f"# Security Report — `{scan_id}`")
    lines.append("")
    if scan_row is not None:
        lines.append(f"- **Mode:** {scan_row['mode']}")
        lines.append(f"- **Target:** `{scan_row['target']}`")
        lines.append(f"- **Model:** {scan_row['model']}")
        lines.append(f"- **Started:** {scan_row['started_at']}")
    lines.append(f"- **Generated:** {datetime.now(timezone.utc).isoformat()}")
    lines.append(f"- **Findings:** {len(findings)}")
    lines.append("")
    lines.append("> All findings are **candidate** until a human reviews and confirms them. "
                 "The model proposes; it does not confirm. Validate each before acting or reporting.")
    lines.append("")

    ordered = sorted(findings, key=lambda r: _SEV_ORDER.get((r["severity"] or "unknown").lower(), 4))

    # summary table
    lines.append("## Summary")
    lines.append("")
    lines.append("| ID | Severity | Class | Location | State |")
    lines.append("|----|----------|-------|----------|-------|")
    for r in ordered:
        lines.append(f"| {r['id']} | {r['severity']} | {r['vuln_class']} | "
                     f"`{r['location']}` | {r['state']} |")
    lines.append("")

    # detail
    lines.append("## Findings")
    lines.append("")
    for r in ordered:
        lines.append(f"### {r['id']} — {r['vuln_class']} ({r['severity']})")
        lines.append("")
        lines.append(f"- **State:** {r['state']}  ·  **Confidence (model):** {r['confidence'] or 'n/a'}")
        lines.append(f"- **Location:** `{r['location']}`")
        lines.append(f"- **Source:** {r['source']}")
        lines.append("")
        if r["description"]:
            lines.append(f"**Why:** {r['description']}")
            lines.append("")
        if r["poc"]:
            lines.append("**Proof of concept (candidate — verify manually):**")
            lines.append("")
            lines.append("```")
            lines.append(r["poc"])
            lines.append("```")
            lines.append("")
        if r["remediation"]:
            lines.append(f"**Remediation:** {r['remediation']}")
            lines.append("")
        try:
            ev = json.loads(r["evidence"])
            lines.append(f"<sub>evidence: {ev.get('model_seconds')}s, "
                         f"in={ev.get('input_tokens')}, out={ev.get('output_tokens')}</sub>")
        except Exception:
            pass
        lines.append("")
        lines.append("---")
        lines.append("")

    return "\n".join(lines)
