"""Self-contained HTML report — styled, no external assets, light/dark aware."""
from __future__ import annotations

import html
import sqlite3

from security_agent.reporting.json_report import build_report

_SEV_COLOR = {
    "critical": "#7f1d1d", "high": "#b91c1c", "medium": "#b45309",
    "low": "#2563eb", "info": "#6b7280", "unknown": "#6b7280",
}

_CSS = """
:root { --bg:#ffffff; --fg:#1f2937; --muted:#6b7280; --card:#f9fafb; --border:#e5e7eb; }
@media (prefers-color-scheme: dark) {
  :root { --bg:#0b0f14; --fg:#e5e7eb; --muted:#9ca3af; --card:#111826; --border:#1f2937; }
}
* { box-sizing: border-box; }
body { margin:0; padding:24px; background:var(--bg); color:var(--fg);
  font:15px/1.5 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif; }
.wrap { max-width: 960px; margin: 0 auto; }
h1 { font-size: 22px; margin: 0 0 4px; }
.meta { color: var(--muted); font-size: 13px; margin-bottom: 16px; }
.note { background: var(--card); border:1px solid var(--border); border-left:4px solid #b45309;
  padding:10px 14px; border-radius:6px; margin:16px 0; font-size:13px; }
table { width:100%; border-collapse: collapse; margin: 12px 0 28px; font-size: 13px; }
th, td { text-align:left; padding:8px 10px; border-bottom:1px solid var(--border); }
th { color: var(--muted); font-weight:600; }
code { background: var(--card); padding:1px 5px; border-radius:4px; font-size:12px; }
.badge { display:inline-block; padding:2px 8px; border-radius:999px; color:#fff;
  font-size:11px; font-weight:700; text-transform:uppercase; letter-spacing:.03em; }
.card { background: var(--card); border:1px solid var(--border); border-radius:8px;
  padding:16px; margin:12px 0; }
.card h3 { margin:0 0 8px; font-size:16px; }
.kv { color: var(--muted); font-size:12px; margin-bottom:8px; }
pre { background: var(--bg); border:1px solid var(--border); border-radius:6px;
  padding:10px; overflow:auto; font-size:12px; }
"""


def _badge(sev: str) -> str:
    s = (sev or "unknown").lower()
    return f'<span class="badge" style="background:{_SEV_COLOR.get(s, "#6b7280")}">{html.escape(s)}</span>'


def render_html(scan_id: str, scan_row: sqlite3.Row | None,
                findings: list[sqlite3.Row]) -> str:
    rep = build_report(scan_id, scan_row, findings)
    e = html.escape
    scan = rep["scan"] or {}
    sev_summary = "  ".join(f"{k}:{v}" for k, v in sorted(rep["summary"]["by_severity"].items()))

    rows = "\n".join(
        f"<tr><td><code>{e(f['id'])}</code></td><td>{_badge(f['severity'])}</td>"
        f"<td>{e(f['vuln_class'])}</td><td><code>{e(f['location'])}</code></td>"
        f"<td>{e(f['state'])}</td></tr>"
        for f in rep["findings"])

    cards = []
    for f in rep["findings"]:
        parts = [f'<div class="card"><h3>{e(f["id"])} — {e(f["vuln_class"])} {_badge(f["severity"])}</h3>']
        parts.append(f'<div class="kv">state: {e(f["state"])} · confidence: '
                     f'{e(f["confidence"] or "n/a")} · source: {e(f["source"])}</div>')
        parts.append(f'<div class="kv">location: <code>{e(f["location"])}</code></div>')
        if f["description"]:
            parts.append(f"<p><strong>Why:</strong> {e(f['description'])}</p>")
        if f["poc"]:
            parts.append("<p><strong>PoC (candidate — verify manually):</strong></p>"
                         f"<pre>{e(f['poc'])}</pre>")
        if f["remediation"]:
            parts.append(f"<p><strong>Remediation:</strong> {e(f['remediation'])}</p>")
        parts.append("</div>")
        cards.append("\n".join(parts))

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Security Report {e(scan_id)}</title><style>{_CSS}</style></head>
<body><div class="wrap">
<h1>Security Report — {e(scan_id)}</h1>
<div class="meta">mode: {e(str(scan.get('mode','?')))} · target: <code>{e(str(scan.get('target','?')))}</code>
 · model: {e(str(scan.get('model','?')))} · generated: {e(rep['generated_at'])}<br>
findings: {rep['summary']['total']} &nbsp; ({e(sev_summary) or 'none'})</div>
<div class="note">{e(rep['disclaimer'])} The model proposes; it does not confirm.</div>
<h2>Summary</h2>
<table><thead><tr><th>ID</th><th>Severity</th><th>Class</th><th>Location</th><th>State</th></tr></thead>
<tbody>{rows or '<tr><td colspan=5>No findings.</td></tr>'}</tbody></table>
<h2>Findings</h2>
{''.join(cards) if cards else '<p>No findings.</p>'}
</div></body></html>
"""
