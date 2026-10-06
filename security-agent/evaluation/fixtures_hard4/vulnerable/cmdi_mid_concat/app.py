"""HARD4/VULN cmdi - 3-file chain, sink file benign-looking, no sanitizer."""
from flask import Flask, request

from builder import ping_cmd
from runner import run

app = Flask(__name__)


@app.route("/ping")
def ping():
    host = request.args.get("host", "")        # SOURCE
    return run(ping_cmd(host))
