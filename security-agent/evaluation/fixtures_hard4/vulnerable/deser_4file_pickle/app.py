"""HARD4/VULN deserialization - 4-file chain app->handle->decode->load(pickle)."""
import base64

from flask import Flask, request

from handler import handle

app = Flask(__name__)


@app.route("/resume")
def resume():
    blob = request.args.get("s", "")           # SOURCE
    return str(handle(base64.b64decode(blob)))
