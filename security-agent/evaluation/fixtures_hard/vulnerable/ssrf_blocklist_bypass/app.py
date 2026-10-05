"""HARD / VULNERABLE — SSRF behind a bypassable blocklist.

Ground truth: SSRF. There IS a guard, but a blocklist of literal strings is
trivially bypassed (decimal/octal/IPv6 IP encodings, alternate metadata names,
DNS rebinding, redirects). A naive reader sees the check and calls it safe.
"""
from urllib.parse import urlparse

import requests
from flask import Flask, request, abort

app = Flask(__name__)
BLOCKED = {"localhost", "127.0.0.1", "169.254.169.254"}


@app.route("/fetch")
def fetch():
    url = request.args.get("url", "")
    host = urlparse(url).hostname or ""
    if host in BLOCKED:                      # blocklist — bypassable
        abort(403)
    # Still SSRF: 127.0.0.1 -> 2130706433 / 0x7f.1 / [::1] / metadata via alt name,
    # and requests follows redirects to internal hosts by default.
    return requests.get(url, timeout=5).text
