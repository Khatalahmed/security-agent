"""HARD/VULN - path traversal via a check-before-decode ordering bug.

Ground truth: path_traversal. There IS a '..' guard, so a quick read calls this
safe. But the guard runs on the still-URL-encoded value, and the string is
percent-decoded AFTERWARDS - so '%2e%2e%2f' sails past the check and becomes a
real '../' before open(). The mitigation is present but applied to the wrong
form of the input; order of operations is the whole bug.
"""
from urllib.parse import unquote

from flask import Flask, request

app = Flask(__name__)
BASE = "/srv/docs/"


@app.route("/doc")
def doc():
    name = request.args.get("name", "")        # SOURCE, still URL-encoded
    if ".." in name:                            # check runs on the ENCODED value
        return "nope", 400
    real = unquote(name)                        # decode happens AFTER the check
    with open(BASE + real) as fh:               # SINK: decoded '../' slips through
        return fh.read()
