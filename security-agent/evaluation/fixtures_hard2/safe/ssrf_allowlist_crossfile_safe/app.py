"""HARD/SAFE - same cross-file fetch shape as the SSRF vuln, but defended.

Ground truth: NO findings. The route hands user input to a cross-file HTTP
helper exactly like the vulnerable twin (so the taint graph proposes the same
candidate chain), but get_json enforces https + a strict host allowlist and
disables redirects, so no attacker-chosen destination is reachable.
"""
from flask import Flask, request

from httpclient import get_json

app = Flask(__name__)


@app.route("/preview")
def preview():
    target = request.args.get("url", "")        # external input, but see helper
    return get_json(target)
