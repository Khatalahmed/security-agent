"""HARD4/SAFE deserialization - same 4-file chain, but the terminal loader uses
json.loads, which cannot instantiate arbitrary objects."""
import base64

from flask import Flask, request

from handler import handle

app = Flask(__name__)


@app.route("/resume")
def resume():
    blob = request.args.get("s", "")
    return str(handle(base64.b64decode(blob)))
