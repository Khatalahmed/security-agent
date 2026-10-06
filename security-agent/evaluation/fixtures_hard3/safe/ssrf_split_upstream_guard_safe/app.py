"""HARD3/SAFE - same three-file SSRF split, but `resource` is checked against a
fixed allowlist UPSTREAM here, and the builder pins a fixed internal host. By the
time fetcher.fetch() runs, the URL can only be one of a few known-safe endpoints.
The fetcher file is unchanged and still looks like an unrestricted SSRF sink.
"""
from flask import Flask, request, abort

from url_builder import build_url
from fetcher import fetch

app = Flask(__name__)
ALLOWED_RESOURCES = {"status", "health", "metrics"}


@app.route("/fetch")
def fetch_resource():
    resource = request.args.get("resource", "")
    if resource not in ALLOWED_RESOURCES:         # UPSTREAM guard: fixed allowlist
        abort(400)
    return fetch(build_url(resource))
