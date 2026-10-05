"""Passive endpoint discovery: parse what a server already advertises.

robots.txt and sitemap.xml are things the site publishes about itself — parsing
them is passive (no extra probing of undisclosed paths). Pure, testable, stdlib.
Sitemap is parsed with a regex (not an XML parser) to avoid any XXE surface.
"""
from __future__ import annotations

import re

_LOC_RE = re.compile(r"<loc>\s*([^<\s]+)\s*</loc>", re.IGNORECASE)


def parse_robots(text: str) -> dict:
    """Return {'disallow': [...], 'allow': [...], 'sitemaps': [...]} from robots.txt."""
    disallow, allow, sitemaps = [], [], []
    for raw in (text or "").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or ":" not in line:
            continue
        key, _, val = line.partition(":")
        key = key.strip().lower()
        val = val.strip()
        if not val:
            continue
        if key == "disallow":
            disallow.append(val)
        elif key == "allow":
            allow.append(val)
        elif key == "sitemap":
            sitemaps.append(val)
    return {"disallow": _dedupe(disallow), "allow": _dedupe(allow),
            "sitemaps": _dedupe(sitemaps)}


def parse_sitemap(xml: str, limit: int = 100) -> list[str]:
    """Return the <loc> URLs from a sitemap.xml (capped)."""
    return _dedupe(_LOC_RE.findall(xml or ""))[:limit]


def _dedupe(items: list[str]) -> list[str]:
    seen, out = set(), []
    for it in items:
        if it not in seen:
            seen.add(it)
            out.append(it)
    return out
