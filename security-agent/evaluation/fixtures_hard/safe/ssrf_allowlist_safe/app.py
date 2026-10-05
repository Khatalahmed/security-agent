"""HARD / SAFE — SSRF-shaped code that is actually safe.

Ground truth: NO findings. User URL is fetched server-side (looks like SSRF),
but it is constrained by a strict scheme + host ALLOWLIST and redirects are
disabled, so the destination cannot be attacker-controlled.
"""
from urllib.parse import urlparse

import requests
from flask import Flask, request, abort

app = Flask(__name__)
ALLOWED_HOSTS = {"api.example.com", "cdn.example.com"}


@app.route("/fetch")
def fetch():
    url = request.args.get("url", "")
    p = urlparse(url)
    if p.scheme != "https" or p.hostname not in ALLOWED_HOSTS:
        abort(403)                            # strict allowlist, not a blocklist
    # allow_redirects=False closes the redirect-to-internal bypass.
    return requests.get(url, timeout=5, allow_redirects=False).text
