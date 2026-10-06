"""HARD4/SAFE cmdi - same loop shape, but each file is validated against a strict
pattern and the command runs via argv with shell=False (no shell parsing)."""
from flask import Flask, request

from runner import run_all

app = Flask(__name__)


@app.route("/convert")
def convert():
    files = request.args.getlist("f")
    return run_all(files)
