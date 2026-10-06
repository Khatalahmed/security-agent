"""HARD4/VULN path traversal - user path joined raw in the middle builder."""
from flask import Flask, request

from pathbuilder import make
from reader import read

app = Flask(__name__)


@app.route("/doc")
def doc():
    name = request.args.get("name", "")        # SOURCE
    return read(make(name))
