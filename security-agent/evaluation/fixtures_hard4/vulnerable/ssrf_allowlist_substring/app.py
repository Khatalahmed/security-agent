"""HARD4/VULN ssrf - allowlist uses a substring test, which is bypassable
(http://evil.com/?x=api.internal, or http://api.internal.evil.com)."""
from flask import Flask, request, abort

from client import fetch

app = Flask(__name__)


@app.route("/fetch")
def f():
    url = request.args.get("url", "")          # SOURCE
    if "api.internal" not in url:               # BROKEN: substring, not host match
        abort(400)
    return fetch(url)
