"""HARD4/SAFE ssti - user text is passed as a bound, autoescaped context variable
into a FIXED template, not concatenated into the template source."""
from flask import Flask, request

from render import show

app = Flask(__name__)


@app.route("/hi")
def hi():
    name = request.args.get("name", "")
    return show(name)
