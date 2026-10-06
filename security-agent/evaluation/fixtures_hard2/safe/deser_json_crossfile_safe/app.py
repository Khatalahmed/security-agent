"""HARD/SAFE - same decode-then-"load state" cross-file shape, but JSON not pickle.

Ground truth: NO findings. Structurally identical to the pickle vuln (base64 ->
cross-file load_state on untrusted bytes), which makes it look equally risky.
It is safe because load_state uses json.loads, which only ever produces inert
data (dicts/lists/strings/numbers) and cannot instantiate arbitrary objects.
"""
import base64

from flask import Flask, request

from session import load_state

app = Flask(__name__)


@app.route("/resume")
def resume():
    blob = request.args.get("state", "")        # untrusted, but see helper
    raw = base64.b64decode(blob)
    return str(load_state(raw))
