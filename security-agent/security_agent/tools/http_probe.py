"""HTTP probing tool for Mode A recon — stdlib only (urllib).

Light-touch and polite by design: one GET per URL, short timeout, capped response
read, an identifying User-Agent, and no automatic following of redirects to hosts
the caller hasn't scope-checked. The header-analysis logic is a pure function so
it is unit-testable without any network.

This tool only gathers evidence. It performs NO active exploitation / payload
injection — that is out of scope for this module by design.
"""
from __future__ import annotations

import re
import ssl
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field

USER_AGENT = "security-agent-recon/0.1 (+authorized-testing-only)"

# Security headers we expect; absence is a low-severity observation.
_SECURITY_HEADERS = {
    "content-security-policy": "Content-Security-Policy",
    "x-content-type-options": "X-Content-Type-Options",
    "x-frame-options": "X-Frame-Options",
    "referrer-policy": "Referrer-Policy",
}
_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)


@dataclass
class ProbeResult:
    url: str
    ok: bool
    status: int | None = None
    final_url: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    title: str = ""
    body_snippet: str = ""
    elapsed_ms: int = 0
    error: str = ""


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Never follow redirects: the target of a 3xx was not scope-checked. The 3xx
    surfaces as an HTTPError response (status + Location header) instead."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def probe(url: str, *, timeout: float = 8.0, max_bytes: int = 65536) -> ProbeResult:
    """Fetch one URL. Never raises for network/HTTP errors — returns ProbeResult."""
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT}, method="GET")
    opener = urllib.request.build_opener(
        _NoRedirect, urllib.request.HTTPSHandler(context=ssl.create_default_context()))
    t0 = time.time()
    try:
        with opener.open(req, timeout=timeout) as resp:
            raw = resp.read(max_bytes)
            headers = {k.lower(): v for k, v in resp.headers.items()}
            body = raw.decode("utf-8", errors="replace")
            m = _TITLE_RE.search(body)
            return ProbeResult(
                url=url, ok=True, status=resp.status,
                final_url=resp.geturl(), headers=headers,
                title=(m.group(1).strip()[:200] if m else ""),
                body_snippet=body[:8192],
                elapsed_ms=int((time.time() - t0) * 1000),
            )
    except urllib.error.HTTPError as e:
        # An HTTP error is still a live response worth recording.
        headers = {k.lower(): v for k, v in (e.headers or {}).items()}
        return ProbeResult(url=url, ok=True, status=e.code, final_url=url,
                           headers=headers, elapsed_ms=int((time.time() - t0) * 1000),
                           error=f"HTTP {e.code}")
    except (urllib.error.URLError, ssl.SSLError, OSError, ValueError) as e:
        return ProbeResult(url=url, ok=False, error=str(e),
                           elapsed_ms=int((time.time() - t0) * 1000))


def analyze_headers(headers: dict[str, str], is_https: bool) -> list[dict]:
    """Pure function: derive low-severity observations from response headers.

    Returns a list of {class, severity, why, evidence} dicts. No network, fully
    deterministic, so it is unit-tested directly.
    """
    h = {k.lower(): v for k, v in headers.items()}
    obs: list[dict] = []

    for key, label in _SECURITY_HEADERS.items():
        if key not in h:
            obs.append({
                "class": "missing-security-header",
                "severity": "low",
                "why": f"Response is missing the {label} header.",
                "evidence": f"no {label}",
            })
    if is_https and "strict-transport-security" not in h:
        obs.append({
            "class": "missing-security-header", "severity": "low",
            "why": "HTTPS response is missing Strict-Transport-Security (HSTS).",
            "evidence": "no Strict-Transport-Security",
        })

    # Version/tech disclosure.
    for key in ("server", "x-powered-by", "x-aspnet-version", "x-generator"):
        if key in h and any(ch.isdigit() for ch in h[key]):
            obs.append({
                "class": "version-disclosure", "severity": "info",
                "why": f"{key} header discloses software/version: {h[key]!r}.",
                "evidence": f"{key}: {h[key]}",
            })
    return obs


def fingerprint(headers: dict[str, str], body_snippet: str) -> list[str]:
    """Best-effort technology fingerprint from headers + body markers."""
    h = {k.lower(): v for k, v in headers.items()}
    tech: set[str] = set()
    server = h.get("server", "").lower()
    powered = h.get("x-powered-by", "").lower()
    for marker, name in (("nginx", "nginx"), ("apache", "Apache"),
                         ("express", "Express"), ("werkzeug", "Flask/Werkzeug"),
                         ("gunicorn", "gunicorn"), ("php", "PHP"),
                         ("asp.net", "ASP.NET")):
        if marker in server or marker in powered:
            tech.add(name)
    cookies = h.get("set-cookie", "").lower()
    if "csrftoken" in cookies or "django" in body_snippet.lower():
        tech.add("Django")
    if "laravel_session" in cookies:
        tech.add("Laravel")
    if "next.js" in body_snippet.lower() or "__next" in body_snippet.lower():
        tech.add("Next.js")
    return sorted(tech)
