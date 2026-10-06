"""HTTP helper that only ever talks to an allowlisted internal API."""
import requests
from urllib.parse import urlparse

ALLOWED_HOSTS = {"api.internal.example.com"}


def get_json(endpoint):
    u = urlparse(endpoint)
    # Fixed scheme + exact host allowlist: user cannot redirect the request to an
    # arbitrary internal address. Redirects disabled so the allowlist can't be
    # bounced through a 302.
    if u.scheme != "https" or u.hostname not in ALLOWED_HOSTS:
        raise ValueError("destination not allowed")
    resp = requests.get(endpoint, timeout=5, allow_redirects=False)
    return {"status": resp.status_code}
