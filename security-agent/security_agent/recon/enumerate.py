"""Passive subdomain enumeration via DNS resolution.

A name-resolution sweep over a small candidate wordlist — DNS queries only, no
HTTP, no zone transfer, no brute-force flooding. The resolver is injectable so
the logic is unit-testable without real DNS. Results are scope-checked by the
caller before anything is probed.
"""
from __future__ import annotations

from typing import Callable

from security_agent.tools import resolve

# Small, conservative candidate list (common hostnames). Kept short on purpose:
# this is light recon, not a brute-force dictionary.
DEFAULT_WORDLIST = [
    "www", "api", "app", "dev", "staging", "test", "admin", "portal",
    "mail", "vpn", "git", "ci", "jenkins", "grafana", "internal", "beta",
    "dashboard", "auth", "status",
]


def enumerate_subdomains(base_domain: str, wordlist: list[str] | None = None,
                         resolver: Callable[[str], tuple[list[str], str]] = resolve,
                         ) -> list[dict]:
    """Return [{'host': sub, 'ips': [...]}] for candidates that resolve."""
    words = wordlist or DEFAULT_WORDLIST
    found: list[dict] = []
    for w in words:
        host = f"{w}.{base_domain}"
        ips, _err = resolver(host)
        if ips:
            found.append({"host": host, "ips": ips})
    return found
