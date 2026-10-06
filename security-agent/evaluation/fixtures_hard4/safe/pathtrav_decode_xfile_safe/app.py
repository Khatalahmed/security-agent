"""HARD4/SAFE path traversal - decode and reduce to a bare filename UPSTREAM,
before the reader ever sees it. Correct order, no escape."""
import os
from urllib.parse import unquote

from flask import Flask, request

from reader import read

app = Flask(__name__)


@app.route("/doc")
def doc():
    name = unquote(request.args.get("name", ""))   # decode FIRST
    safe = os.path.basename(name)                   # strip directory parts
    return read(safe)
