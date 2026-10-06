"""HARD4/VULN cmdi - user args concatenated into a shell command inside a loop."""
from flask import Flask, request

from runner import run_all

app = Flask(__name__)


@app.route("/convert")
def convert():
    files = request.args.getlist("f")          # SOURCE (list)
    return run_all(files)
