"""Cross-file taint: SOURCE here, SINK in util.py. Per-file analysis misses this."""
from flask import Flask, request
from util import run_ping

app = Flask(__name__)


@app.route("/ping")
def ping():
    host = request.args.get("host", "")   # SOURCE: external input
    return run_ping(host)                  # flows across files
