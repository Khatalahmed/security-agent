"""HARD/VULN - insecure deserialization through a cross-file "load state" helper.

Ground truth: deserialization. A base64 blob from the request is decoded and
passed across a file to load_state(), which pickle.loads() it. pickle on
attacker-controlled bytes is arbitrary code execution. The sink module reads
like a neutral persistence helper; the taint from the request is what makes it
a remote-code-execution hole.
"""
import base64

from flask import Flask, request

from session import load_state

app = Flask(__name__)


@app.route("/resume")
def resume():
    blob = request.args.get("state", "")        # SOURCE: attacker-controlled
    raw = base64.b64decode(blob)
    return str(load_state(raw))                  # flows across files to pickle
