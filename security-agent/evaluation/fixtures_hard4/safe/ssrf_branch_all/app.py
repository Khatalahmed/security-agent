"""HARD4/SAFE ssrf - the host allowlist is enforced UNCONDITIONALLY on every
path before the fetch (contrast: the vuln twin guarded only one branch)."""
from flask import Flask, request, abort
from urllib.parse import urlparse

from client import fetch

app = Flask(__name__)


@app.route("/fetch")
def f():
    url = request.args.get("url", "")
    if urlparse(url).hostname != "api.internal":   # guard on ALL paths
        abort(400)
    return fetch(url)
