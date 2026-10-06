"""HARD4/SAFE path traversal - the middle builder basename()s the user value and
anchors it under a fixed directory, so no '../' escape. Reader unchanged."""
from flask import Flask, request

from pathbuilder import make
from reader import read

app = Flask(__name__)


@app.route("/doc")
def doc():
    name = request.args.get("name", "")
    return read(make(name))
