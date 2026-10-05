"""Reporting layer: Markdown, JSON, HTML, SARIF renderers."""
from security_agent.reporting.markdown import render_markdown
from security_agent.reporting.json_report import render_json, build_report
from security_agent.reporting.html import render_html
from security_agent.reporting.sarif import render_sarif

# format name -> (renderer, file extension)
RENDERERS = {
    "md": (render_markdown, "md"),
    "json": (render_json, "json"),
    "html": (render_html, "html"),
    "sarif": (render_sarif, "sarif"),
}

__all__ = ["render_markdown", "render_json", "render_html", "render_sarif",
           "build_report", "RENDERERS"]
