"""Fixture: SAFE — file serving done correctly.

Ground truth: NO findings. The filename is reduced to its basename and matched
against a fixed allowlist, so no traversal is possible.
"""
import os

from flask import Flask, request, send_file, abort

app = Flask(__name__)
DOCS = os.path.join(os.path.dirname(__file__), "docs")
ALLOWED = {"readme.txt", "terms.txt", "privacy.txt"}


@app.route("/doc")
def read_doc():
    # Strip any directory components, then require an exact allowlist match.
    requested = request.args.get("name", "")
    name = os.path.basename(requested)
    if name not in ALLOWED:
        abort(404)
    return send_file(os.path.join(DOCS, name))
