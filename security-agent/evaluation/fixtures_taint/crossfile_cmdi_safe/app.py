"""Cross-file, but safe: allowlist at the source, no shell at the sink."""
from flask import Flask, request, abort
from util import run_ping

app = Flask(__name__)
ALLOWED = {"api.example.com", "cdn.example.com"}


@app.route("/ping")
def ping():
    host = request.args.get("host", "")
    if host not in ALLOWED:
        abort(400)
    return run_ping(host)
