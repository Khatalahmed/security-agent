"""Attack-surface profiler for Mode A (recon).

Given an already-scope-checked host, gathers a light-touch profile — DNS, which
schemes answer, server/tech fingerprint, response headers, and a small set of
well-known paths — and derives deterministic recon findings (missing security
headers, version disclosure, exposed sensitive files).

All requests are read-only GETs, rate-limited, and performed only on the host the
caller authorized. No active exploitation.
"""
from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from urllib.parse import urlparse

from security_agent.findings.models import Finding, State
from security_agent.recon.parse import parse_robots, parse_sitemap
from security_agent.tools import analyze_headers, fingerprint, probe, resolve

# Standard, non-destructive paths. The sensitive ones (.git/config, .env) are
# plain GETs; a 200 is a high-severity exposure, not an exploit.
WELL_KNOWN = [
    "/robots.txt", "/sitemap.xml", "/.well-known/security.txt",
    "/.git/config", "/.env",
]
_SENSITIVE = {"/.git/config", "/.env"}
# What the real file looks like. Catch-all/SPA servers answer 200 with an HTML
# page for any path, so a bare 200 is not evidence of exposure.
_SENSITIVE_SIGNATURE = {
    "/.git/config": re.compile(r"^\s*\[core\]", re.MULTILINE),
    "/.env": re.compile(r"^\s*[A-Za-z_][A-Za-z0-9_]*\s*=", re.MULTILINE),
}

_SEV_LABEL = {
    "missing-security-header": ("Missing Security Header", "low"),
    "version-disclosure": ("Version/Tech Disclosure", "info"),
    "exposed-sensitive-file": ("Exposed Sensitive File", "high"),
}


@dataclass
class AttackSurface:
    host: str
    ips: list[str] = field(default_factory=list)
    dns_error: str = ""
    schemes: list[dict] = field(default_factory=list)      # [{scheme,status,final_url,title,server}]
    technologies: list[str] = field(default_factory=list)
    primary_url: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    discovered_paths: list[dict] = field(default_factory=list)   # [{path,status,sensitive}]
    discovered_endpoints: list[str] = field(default_factory=list)  # from robots/sitemap
    observations: list[dict] = field(default_factory=list)       # from analyze_headers + path checks


class _RateLimiter:
    def __init__(self, max_rps: float):
        self._min_interval = 1.0 / max_rps if max_rps and max_rps > 0 else 0.0
        self._last = 0.0

    def wait(self) -> None:
        if self._min_interval <= 0:
            return
        delta = time.time() - self._last
        if delta < self._min_interval:
            time.sleep(self._min_interval - delta)
        self._last = time.time()


def profile_target(target: str, *, host: str | None = None, max_rps: float = 2.0,
                   timeout: float = 8.0, on_progress=lambda m: None) -> AttackSurface:
    """Profile an authorized target. `target` may be a bare host or a full URL
    (scheme/port honored); `host` overrides the display/DNS host if given."""
    parsed = urlparse(target if "://" in target else "//" + target, scheme="")
    host = host or parsed.hostname or target
    # Origins to probe: an explicit scheme/port is honored; otherwise try both.
    if parsed.scheme in ("http", "https") and parsed.netloc:
        origins = [f"{parsed.scheme}://{parsed.netloc}"]
    else:
        origins = [f"https://{host}", f"http://{host}"]

    surface = AttackSurface(host=host)
    rl = _RateLimiter(max_rps)

    on_progress(f"resolving {host} ...")
    surface.ips, surface.dns_error = resolve(host)
    if surface.ips:
        on_progress(f"  DNS: {', '.join(surface.ips)}")
    elif surface.dns_error:
        on_progress(f"  DNS failed: {surface.dns_error}")

    for origin in origins:
        scheme = urlparse(origin).scheme
        rl.wait()
        on_progress(f"probing {origin} ...")
        r = probe(origin, timeout=timeout)
        if not r.ok:
            continue
        server = r.headers.get("server", "")
        surface.schemes.append({"scheme": scheme, "status": r.status,
                                "final_url": r.final_url, "title": r.title, "server": server})
        if not surface.primary_url:
            surface.primary_url = origin
            surface.headers = r.headers
            surface.technologies = fingerprint(r.headers, r.body_snippet)
            surface.observations.extend(analyze_headers(r.headers, is_https=(scheme == "https")))

    if not surface.primary_url:
        on_progress("  no HTTP(S) response on 80/443")
        return surface

    # Well-known / sensitive-file checks on the primary scheme.
    for path in WELL_KNOWN:
        rl.wait()
        r = probe(surface.primary_url + path, timeout=timeout)
        if r.ok and r.status == 200:
            sensitive = path in _SENSITIVE
            if sensitive and (r.body_snippet.lstrip().startswith("<")
                              or not _SENSITIVE_SIGNATURE[path].search(r.body_snippet)):
                on_progress(f"  {path} -> 200 but content doesn't match (catch-all page); ignored")
                continue
            surface.discovered_paths.append({"path": path, "status": 200, "sensitive": sensitive})
            on_progress(f"  found {path} (200){' [SENSITIVE]' if sensitive else ''}")
            # Passive endpoint discovery: parse what the server advertises.
            if path == "/robots.txt":
                rob = parse_robots(r.body_snippet)
                surface.discovered_endpoints += rob["disallow"] + rob["allow"]
            elif path == "/sitemap.xml":
                surface.discovered_endpoints += parse_sitemap(r.body_snippet)
            if sensitive:
                surface.observations.append({
                    "class": "exposed-sensitive-file", "severity": "high",
                    "why": f"{path} is publicly readable and may leak secrets or source.",
                    "evidence": f"GET {path} -> 200",
                })

    # dedupe discovered endpoints, preserving order
    seen: set[str] = set()
    surface.discovered_endpoints = [
        e for e in surface.discovered_endpoints if not (e in seen or seen.add(e))
    ]
    if surface.discovered_endpoints:
        on_progress(f"  {len(surface.discovered_endpoints)} endpoint(s) from robots/sitemap")
    return surface


def surface_to_findings(surface: AttackSurface, scan_id: str, start_index: int = 1) -> list[Finding]:
    """Deterministic recon findings from the profile. All CANDIDATE."""
    findings: list[Finding] = []
    counter = start_index
    for obs in surface.observations:
        label, _default_sev = _SEV_LABEL.get(obs["class"], (obs["class"], "info"))
        detail = obs.get("evidence", "")
        # Make each observation a distinct finding: fold the specific header/file
        # into the class so 4 missing headers don't collapse into one under dedup,
        # and carry `detail` as the line signature so same-label observations
        # (e.g. two version-disclosure headers) also stay separate.
        if obs["class"] == "missing-security-header":
            vuln_class = f"Missing Security Header: {detail.replace('no ', '').strip()}"
        else:
            vuln_class = label
        fid = f"F-{scan_id}-{counter:03d}"
        counter += 1
        findings.append(Finding(
            id=fid, scan_id=scan_id, source="recon:probe", target=surface.host,
            vuln_class=vuln_class, severity=obs.get("severity", "info"),
            location=surface.primary_url or surface.host,
            description=obs.get("why", ""),
            remediation="", state=State.CANDIDATE,
            evidence={"host": surface.host, "ips": surface.ips,
                      "technologies": surface.technologies,
                      "raw_item": {"line_hint": detail}},
        ))
    return findings


def surface_summary(surface: AttackSurface) -> str:
    """Compact text profile for the report and the recon LLM skill."""
    lines = [f"Host: {surface.host}",
             f"IPs: {', '.join(surface.ips) or '(unresolved)'}"]
    for s in surface.schemes:
        lines.append(f"{s['scheme']}: {s['status']} {s['final_url']} "
                     f"server={s['server'] or '?'} title={s['title'] or ''}")
    lines.append(f"Technologies: {', '.join(surface.technologies) or 'unknown'}")
    if surface.discovered_paths:
        lines.append("Discovered paths: " +
                     ", ".join(f"{p['path']}{'[SENSITIVE]' if p['sensitive'] else ''}"
                               for p in surface.discovered_paths))
    if surface.discovered_endpoints:
        sample = surface.discovered_endpoints[:20]
        more = f" (+{len(surface.discovered_endpoints) - len(sample)} more)" if len(surface.discovered_endpoints) > len(sample) else ""
        lines.append(f"Endpoints (robots/sitemap): {', '.join(sample)}{more}")
    if surface.observations:
        lines.append("Observations: " +
                     "; ".join(f"{o['class']}({o['severity']})" for o in surface.observations))
    return "\n".join(lines)
