"""HARD4/VULN ssti - user text concatenated into the template SOURCE, cross-file."""
from flask import Flask, request

from render import show

app = Flask(__name__)


@app.route("/hi")
def hi():
    name = request.args.get("name", "")        # SOURCE
    return show(name)
