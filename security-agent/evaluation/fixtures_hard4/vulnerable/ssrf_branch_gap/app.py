"""HARD4/VULN ssrf - the host allowlist is only enforced on one branch; the
default path reaches the fetch unguarded."""
from flask import Flask, request, abort
from urllib.parse import urlparse

from client import fetch

app = Flask(__name__)


@app.route("/fetch")
def f():
    url = request.args.get("url", "")          # SOURCE
    mode = request.args.get("mode", "fast")
    if mode == "checked":                       # guard ONLY when mode=checked
        if urlparse(url).hostname != "api.internal":
            abort(400)
    return fetch(url)                           # default 'fast' path is unguarded
