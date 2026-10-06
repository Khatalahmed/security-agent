"""Unchanged from the vuln twin: in isolation this is an unrestricted fetch.
Safe only because of the upstream allowlist + fixed host (not visible here)."""
import requests


def fetch(url):
    return requests.get(url, timeout=5).text[:200]  # looks like SSRF in isolation
