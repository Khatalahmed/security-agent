"""Safety layer: refuse-by-default scope guard for LIVE target scanning.

The guard is the spine of the platform: a target that is not explicitly
authorized in the scope allowlist is refused. Every decision is logged by the
caller via the audit log.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urlparse


@dataclass
class ScopeDecision:
    target: str
    host: str
    allowed: bool
    reason: str


def normalize_host(target: str) -> str:
    """Extract a bare hostname from a target string (URL, host, or host:port)."""
    t = target.strip().lower()
    if "://" in t:
        t = urlparse(t).netloc or urlparse(t).path
    # strip userinfo and port
    t = t.split("@")[-1]
    t = t.split(":")[0]
    t = t.strip("/")
    return t


_HOST_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9_-]{1,63}\.)*[a-z0-9_-]{1,63}$")


class ScopeGuard:
    """Refuse-by-default allowlist.

    Entries:
      - "example.com"   matches exactly example.com
      - ".example.com"  matches any subdomain of example.com
    An IP or host matches only by exact entry.
    """

    def __init__(self, entries: list[str]):
        self.entries = [e.lower() for e in entries]

    def check(self, target: str) -> ScopeDecision:
        host = normalize_host(target)
        if not host:
            return ScopeDecision(target, host, False, "could not parse a host from target")
        if not _HOST_RE.match(host):
            # not a hostname (could be a path/garbage); refuse
            return ScopeDecision(target, host, False, f"'{host}' is not a valid hostname")
        if not self.entries:
            return ScopeDecision(target, host, False, "scope allowlist is empty (refuse-by-default)")

        for entry in self.entries:
            if entry.startswith("."):
                base = entry[1:]
                if host == base or host.endswith("." + base):
                    return ScopeDecision(target, host, True, f"matched subdomain rule '{entry}'")
            elif host == entry:
                return ScopeDecision(target, host, True, f"matched exact rule '{entry}'")
        return ScopeDecision(target, host, False, "no matching scope entry")
