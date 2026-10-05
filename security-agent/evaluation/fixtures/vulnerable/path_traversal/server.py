"""Fixture: VULNERABLE — path traversal / local file inclusion.

Ground truth: one high-severity path-traversal bug in `read_doc`.
"""
import os

from flask import Flask, request, send_file

app = Flask(__name__)
DOCS = os.path.join(os.path.dirname(__file__), "docs")


@app.route("/doc")
def read_doc():
    # `name` is joined into a path with no sanitization or containment check:
    # /doc?name=../../../../etc/passwd  escapes DOCS entirely.
    name = request.args.get("name", "")
    path = os.path.join(DOCS, name)
    return send_file(path)
