"""HARD/SAFE - the same decode/open shapes, but ordered and anchored correctly.

Ground truth: NO findings. Looks dangerous (user input reaching open()), but the
value is decoded FIRST, reduced to a bare filename with basename(), joined under
a fixed base, and the resolved absolute path is confirmed to stay inside BASE.
No ordering gap, no escape.
"""
import os
from urllib.parse import unquote

from flask import Flask, request

app = Flask(__name__)
BASE = "/srv/docs"


@app.route("/doc")
def doc():
    name = unquote(request.args.get("name", ""))    # decode FIRST
    safe = os.path.basename(name)                    # drop any directory parts
    path = os.path.join(BASE, safe)
    if not os.path.abspath(path).startswith(BASE + os.sep):
        return "nope", 400                           # defense in depth
    with open(path) as fh:
        return fh.read()
