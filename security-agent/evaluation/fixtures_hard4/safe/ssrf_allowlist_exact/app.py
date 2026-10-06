"""HARD4/SAFE ssrf - exact host match (parsed hostname == allowlisted host),
not a bypassable substring test. Client unchanged."""
from flask import Flask, request, abort
from urllib.parse import urlparse

from client import fetch

app = Flask(__name__)

ALLOWED = {"api.internal"}


@app.route("/fetch")
def f():
    url = request.args.get("url", "")
    if urlparse(url).hostname not in ALLOWED:   # exact host match
        abort(400)
    return fetch(url)
